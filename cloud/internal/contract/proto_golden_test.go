// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package contract

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	agentv1 "github.com/glowfly/pail/services/proto/agentv1"
	operatorv1 "github.com/glowfly/pail/services/proto/operatorv1"
	pailv1 "github.com/glowfly/pail/services/proto/pailv1"
	tokenv1 "github.com/glowfly/pail/services/proto/tokenv1"
)

// extraWireFiles is filled by init() in files that travel with a different
// bundle (proto_golden_ha_test.go registers ha_replication.proto, which is not
// part of the public distribution). The golden vector still lists every file;
// rows for a package that no registered descriptor declares are reported and
// set aside — never silently — so the same frozen vector serves both trees.
var extraWireFiles []protoreflect.FileDescriptor

// TestGCTR02_WireSchemaFrozen — G-CTR-02 .
//
// proto_schema.vec(손 전사)와 생성 디스크립터의 실제 (full_name, number,
// kind, cardinality) 집합을 양방향 대조한다.
//
//	PG-01 골든 ⊆ 디스크립터 — 골든에 있는데 실물에 없으면 필드 삭제/개명
//	PG-02 디스크립터 ⊆ 골든 — 실물에 있는데 골든에 없으면 무단 추가
//	PG-03 메시지 안 번호 유일 — 현재 시점의 중복만 본다
//	PG-04 순회 대상이 정확히 5파일 — 새 proto 를 추가하고 골든에 안 올리는 것을 막는다
//	PG-05 reserved 양방향 — PG-01~04 넷 다 reserved 를 안 보므로 별도 관측점 (E-W1 §3.2)
//
// PG-05 가 여는 자리: 필드를 지우고 그 번호를 다른 타입으로 되쓰면 PG-01/02 가
// 골든과의 차이로 잡지만 **골든을 함께 고치면 통과한다**. reserved 는 그
// "함께 고치기"를 protoc 단계에서 막고, PG-05 는 그 reserved 자체가 조용히
// 사라지는 것을 막는다.
//
// 다섯 다 **체크인된 생성 디스크립터**만 읽는다 — proto/*.proto 원문은 어느
// 검사에도 안 들어간다. 재생성 없이 원문만 고친 변경은 여기서 전부 침묵한다.
// 그 사각지대는 tests/tools/proto_contract_check.py (PS-01~03) 가 맡는다.
func TestGCTR02_WireSchemaFrozen(t *testing.T) {
	files := append([]protoreflect.FileDescriptor{
		pailv1.File_pail_proto,
		tokenv1.File_token_service_proto,
		operatorv1.File_operator_service_proto,
		agentv1.File_agent_relay_proto,
	}, extraWireFiles...)

	// 실물 집합 구성 — 골든과 같은 행 문법으로 직렬화해 문자열 집합으로 비교한다.
	actual := map[string]bool{}
	actualReserved := map[string]bool{}
	var actualFiles []string
	registered := map[string]bool{}
	for _, fd := range files {
		registered[string(fd.Package())] = true
		line := fmt.Sprintf("file\t%s\t%s", fd.Path(), fd.Package())
		actual[line] = true
		actualFiles = append(actualFiles, line)
		walkMessages(fd.Messages(), func(md protoreflect.MessageDescriptor) {
			for i := 0; i < md.Fields().Len(); i++ {
				f := md.Fields().Get(i)
				actual[fmt.Sprintf("field\t%s\t%d\t%s\t%s",
					f.FullName(), f.Number(), f.Kind(), f.Cardinality())] = true
			}
			collectMessageReserved(md, actualReserved)
			collectEnumReserved(md.Enums(), actualReserved)
			collectEnums(md.Enums(), actual)
		})
		collectEnumReserved(fd.Enums(), actualReserved)
		collectEnums(fd.Enums(), actual)
	}

	// 골든 집합. reserved 행은 따로 담는다 — 같은 집합에 넣으면 PG-01/02 가
	// 먼저 잡아 PG-05 의 판정이 남의 이름으로 보고된다 (H-B9).
	rows := readFlatVec(t, goldenPath(t, "tests/golden/contract/proto_schema.vec"))
	// 골든이 드는 패키지 중 이 트리에 등록된 디스크립터가 없는 것 — 다른 묶음으로
	// 가는 파일이다. 그 패키지의 행만 옆에 세워 두고, 몇 건인지 적는다. 등록도
	// 안 됐고 골든 file 행에도 없는 패키지의 행은 세워 두지 않는다(PG-01 이 잡는다).
	absent := map[string]bool{}
	for _, cols := range rows {
		if cols[0] == "file" && len(cols) == 3 && !registered[cols[2]] {
			absent[cols[2]] = true
		}
	}
	pkgOf := func(cols []string) string {
		if cols[0] == "file" && len(cols) == 3 {
			return cols[2]
		}
		for p := range absent {
			if len(cols) > 1 && strings.HasPrefix(cols[1], p+".") {
				return p
			}
		}
		return ""
	}
	setAside := 0
	golden := map[string]bool{}
	goldenReserved := map[string]bool{}
	var goldenFiles []string
	for _, cols := range rows {
		if p := pkgOf(cols); p != "" && absent[p] {
			setAside++
			continue
		}
		line := strings.Join(cols, "\t")
		if cols[0] == "reserved" {
			if len(cols) != 5 && len(cols) != 4 {
				t.Fatalf("reserved 행 칼럼 %d — range 는 5, name 은 4 여야 한다: %v", len(cols), cols)
			}
			if goldenReserved[line] {
				t.Fatalf("골든 reserved 행 중복: %s", line)
			}
			goldenReserved[line] = true
			continue
		}
		if golden[line] {
			t.Fatalf("골든 행 중복: %s", line)
		}
		golden[line] = true
		if cols[0] == "file" {
			goldenFiles = append(goldenFiles, line)
		}
	}

	// PG-04: 파일 리터럴 정확 일치 (순서 포함). 등록된 디스크립터 수가 기준이다 —
	// 전체 트리에서 5, ha_replication.proto 가 없는 배포에서 4.
	if len(absent) > 0 {
		var names []string
		for p := range absent {
			names = append(names, p)
		}
		sort.Strings(names)
		t.Logf("PG-04: golden rows for %d package(s) with no registered descriptor in this tree were set aside (%d rows): %v",
			len(absent), setAside, names)
	}
	if len(goldenFiles) != len(files) || len(actualFiles) != len(files) {
		t.Fatalf("PG-04: file 행 골든 %d / 실물 %d — 등록 디스크립터 %d 와 같아야 한다", len(goldenFiles), len(actualFiles), len(files))
	}
	for i := range actualFiles {
		if goldenFiles[i] != actualFiles[i] {
			t.Errorf("PG-04: file 행 불일치\n golden=%s\n actual=%s", goldenFiles[i], actualFiles[i])
		}
	}

	// PG-01: 골든 ⊆ 실물.
	var missing []string
	for line := range golden {
		if !actual[line] {
			missing = append(missing, line)
		}
	}
	sort.Strings(missing)
	for _, l := range missing {
		t.Errorf("PG-01: 골든에 있으나 디스크립터에 없음 (삭제/개명/번호 변경): %s", l)
	}

	// PG-02: 실물 ⊆ 골든.
	var extra []string
	for line := range actual {
		if !golden[line] {
			extra = append(extra, line)
		}
	}
	sort.Strings(extra)
	for _, l := range extra {
		t.Errorf("PG-02: 디스크립터에 있으나 골든에 없음 (무단 추가 — 골든 갱신은 의도 선언이다): %s", l)
	}

	// PG-03: 골든의 field 행에서 메시지별 번호·이름 유일성.
	type key struct{ msg, num string }
	byNum := map[key]string{}
	byName := map[string]bool{}
	for _, cols := range rows {
		if cols[0] != "field" {
			continue
		}
		if len(cols) != 5 {
			t.Fatalf("field 행 칼럼 %d — 5 여야 한다: %v", len(cols), cols)
		}
		full, num := cols[1], cols[2]
		dot := strings.LastIndex(full, ".")
		msg, name := full[:dot], full[dot+1:]
		k := key{msg, num}
		if prev, dup := byNum[k]; dup {
			t.Errorf("PG-03: %s 번호 %s 재사용 — %s ↔ %s (reserved 부재의 대가)", msg, num, prev, name)
		}
		byNum[k] = name
		if byName[full] {
			t.Errorf("PG-03: 필드 이름 중복: %s", full)
		}
		byName[full] = true
	}

	// PG-05: reserved 양방향.
	var resMissing, resExtra []string
	for line := range goldenReserved {
		if !actualReserved[line] {
			resMissing = append(resMissing, line)
		}
	}
	for line := range actualReserved {
		if !goldenReserved[line] {
			resExtra = append(resExtra, line)
		}
	}
	sort.Strings(resMissing)
	sort.Strings(resExtra)
	for _, l := range resMissing {
		t.Errorf("PG-05: 골든에 있으나 디스크립터에 없음 — reserved 가 지워졌거나 재생성이 안 됐다: %s", l)
	}
	for _, l := range resExtra {
		t.Errorf("PG-05: 디스크립터에 있으나 골든에 없음 — reserved 추가는 의도 선언이다: %s", l)
	}

	t.Logf("GOLDEN-SCHEMA go files=%d rows=%d actual=%d reserved=%d/%d ok=%v",
		len(actualFiles), len(golden), len(actual),
		len(goldenReserved), len(actualReserved), !t.Failed())
}

// collectMessageReserved — 메시지의 reserved 번호 구간·이름.
// protoreflect 의 FieldRanges 는 **반열린 구간** [start, end) 다. 골든은 사람이
// 읽는 닫힌 구간이라 hi = end-1 로 옮긴다. 아래 collectEnumReserved 의
// EnumRanges 는 **닫힌 구간**이라 그대로 쓴다 — 둘의 규약이 다르다.
func collectMessageReserved(md protoreflect.MessageDescriptor, into map[string]bool) {
	rr := md.ReservedRanges()
	for i := 0; i < rr.Len(); i++ {
		r := rr.Get(i)
		into[fmt.Sprintf("reserved\t%s\trange\t%d\t%d", md.FullName(), r[0], r[1]-1)] = true
	}
	rn := md.ReservedNames()
	for i := 0; i < rn.Len(); i++ {
		into[fmt.Sprintf("reserved\t%s\tname\t%s", md.FullName(), rn.Get(i))] = true
	}
}

func collectEnumReserved(eds protoreflect.EnumDescriptors, into map[string]bool) {
	for i := 0; i < eds.Len(); i++ {
		ed := eds.Get(i)
		rr := ed.ReservedRanges()
		for j := 0; j < rr.Len(); j++ {
			r := rr.Get(j)
			into[fmt.Sprintf("reserved\t%s\trange\t%d\t%d", ed.FullName(), r[0], r[1])] = true
		}
		rn := ed.ReservedNames()
		for j := 0; j < rn.Len(); j++ {
			into[fmt.Sprintf("reserved\t%s\tname\t%s", ed.FullName(), rn.Get(j))] = true
		}
	}
}

func walkMessages(mds protoreflect.MessageDescriptors, fn func(protoreflect.MessageDescriptor)) {
	for i := 0; i < mds.Len(); i++ {
		md := mds.Get(i)
		if md.IsMapEntry() {
			// 합성 map entry — 실측상 map 0건이나, 생기면 field 행이 아니라
			// 본 필드의 kind 로 드러나야 한다.
			continue
		}
		fn(md)
		walkMessages(md.Messages(), fn)
	}
}

// collectEnums — enum 값 행. protoreflect 의 값 FullName 은 C++ 스코핑이라
// 부모 스코프에 붙는다(pail.v1.ACTION_MOVE). 골든은 사람이 읽는
// <EnumFullName>.<VALUE> 를 쓰므로 여기서 조립한다.
func collectEnums(eds protoreflect.EnumDescriptors, into map[string]bool) {
	for i := 0; i < eds.Len(); i++ {
		ed := eds.Get(i)
		for j := 0; j < ed.Values().Len(); j++ {
			v := ed.Values().Get(j)
			into[fmt.Sprintf("enum\t%s.%s\t%d", ed.FullName(), v.Name(), v.Number())] = true
		}
	}
}
