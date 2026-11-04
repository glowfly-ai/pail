# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Fresh software-only PKI using OpenSSL; private material stays in private volumes."""
import datetime
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile


def openssl(*args):
    return subprocess.check_output(['openssl', *map(str, args)], stderr=subprocess.PIPE)


def provision(state, rows):
    """Run ONLY in the owned prepare container. CA key is temporary and not exported."""
    records, entries, requesters = [], [], []
    first = state / 'robots' / rows[0]['key']
    with tempfile.TemporaryDirectory(prefix='pail-fleet-ca-') as temp:
        ca = Path(temp)
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '7',
                '-subj', '/CN=PAIL software fleet test CA', '-keyout', ca/'ca.key', '-out', ca/'ca.crt')
        (ca/'ca.key').chmod(0o600)

        def leaf(dest, name, purpose, sans):
            dest.mkdir(parents=True, exist_ok=True); dest.chmod(0o700)
            key, cert = dest/(name+'.key'), dest/(name+'.crt')
            if key.exists() or cert.exists():
                raise RuntimeError('NEW_TLS_MATERIAL_REQUIRED')
            req = ca/(name+'.csr'); ext = ca/(name+'.ext')
            openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN='+name,
                    '-keyout', key, '-out', req)
            key.chmod(0o600)
            ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+purpose+'\nsubjectAltName='+sans+'\n')
            openssl('x509', '-req', '-in', req, '-CA', ca/'ca.crt', '-CAkey', ca/'ca.key',
                    '-set_serial', str(int.from_bytes(os.urandom(16),'big')), '-days','7','-sha256',
                    '-extfile',ext,'-out',cert)
            cert.chmod(0o644)
            fp=hashlib.sha256(openssl('x509','-in',cert,'-outform','DER')).hexdigest()
            end=openssl('x509','-in',cert,'-enddate','-noout').decode().strip().split('=',1)[1]
            expiry=datetime.datetime.strptime(end,'%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc).isoformat()
            return fp, expiry

        issuer = first/'private/config/grpc_certs'
        fp, exp=leaf(issuer,'server','serverAuth','DNS:issuer,DNS:localhost,IP:127.0.0.1')
        (issuer/'ca.crt').write_bytes((ca/'ca.crt').read_bytes())
        records.append({'component':'issuer','server_fingerprint':fp,'not_after':exp})
        for row in rows:
            base=state/'robots'/row['key']; tls=base/'private/agent-key/grpc_certs'
            sfp,exp=leaf(tls,'server','serverAuth','DNS:agent,DNS:localhost,IP:127.0.0.1,DNS:'+row['services']['agent'])
            cfp,exp=leaf(tls,'client','clientAuth','DNS:'+row['key'])
            entries.append({'robot_id':row['robot_id'],'role':'robot','fingerprints':[cfp]})
            requesters.append({'match':{'caller':'mtls','cert_sha256':cfp},'kind':'system',
                               'id':'demo-'+row['key'],'skills':['twist','wave','walk','roulade','kick_left','kick_right']})
            public=base/'public/config/grpc_certs';public.mkdir(parents=True,exist_ok=True)
            (public/'ca.crt').write_bytes((ca/'ca.crt').read_bytes())
            records.append({'component':'agent','robot_id':row['robot_id'],'client_fingerprint':cfp,
                            'server_fingerprint':sfp,'not_after':exp})
    return {'version':1,'robots':entries}, {'version':1,'requesters':requesters}, records


def provision_push(state, rows):
    """Certificates of the observation upload (design 15.1): a CA of its own, the collector's server
    certificate and one client certificate per robot's observer. Run ONLY in the owned prepare
    container; the CA key is temporary and not exported. Returns the observers' fingerprints by
    robot (for the registry) and a public receipt without private material."""
    first = state / 'robots' / rows[0]['key']
    fingerprints, records = {}, []
    with tempfile.TemporaryDirectory(prefix='pail-push-ca-') as temp:
        ca = Path(temp)
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '7',
                '-subj', '/CN=PAIL observation upload test CA', '-keyout', ca/'ca.key', '-out', ca/'ca.crt')
        (ca/'ca.key').chmod(0o600)

        def leaf(dest, name, purpose, sans):
            dest.mkdir(parents=True, exist_ok=True); dest.chmod(0o700)
            key, cert = dest/(name+'.key'), dest/(name+'.crt')
            if key.exists() or cert.exists():
                raise RuntimeError('NEW_TLS_MATERIAL_REQUIRED')
            req = ca/(name+'.csr'); ext = ca/(name+'.ext')
            openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN='+name, '-keyout', key, '-out', req)
            key.chmod(0o600)
            ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+purpose+'\nsubjectAltName='+sans+'\n')
            openssl('x509', '-req', '-in', req, '-CA', ca/'ca.crt', '-CAkey', ca/'ca.key',
                    '-set_serial', str(int.from_bytes(os.urandom(16),'big')), '-days','7','-sha256', '-extfile',ext,'-out',cert)
            cert.chmod(0o644)
            (dest/'ca.crt').write_bytes((ca/'ca.crt').read_bytes()); (dest/'ca.crt').chmod(0o644)
            fp=hashlib.sha256(openssl('x509','-in',cert,'-outform','DER')).hexdigest()
            end=openssl('x509','-in',cert,'-enddate','-noout').decode().strip().split('=',1)[1]
            expiry=datetime.datetime.strptime(end,'%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc).isoformat()
            return fp, expiry

        sfp, exp = leaf(first/'private/config/push_certs', 'server', 'serverAuth', 'DNS:collector,DNS:localhost,IP:127.0.0.1')
        records.append({'component': 'collector', 'server_fingerprint': sfp, 'not_after': exp})
        for row in rows:
            cfp, exp = leaf(state/'robots'/row['key']/'private/observer-key/push_certs', 'client', 'clientAuth', 'DNS:'+row['key']+'-observer')
            fingerprints[row['robot_id']] = cfp
            records.append({'component': 'observer', 'robot_id': row['robot_id'], 'client_fingerprint': cfp, 'not_after': exp})
    return fingerprints, records
