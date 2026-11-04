// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

// What the capability document says about the sources behind the screen
// (design 8.3): a tab or a column without a source is not drawn.

// declares reports whether the source map has a provider of this kind.
func (c *Collector) declares(kind string) bool {
	for _, p := range c.config.Providers {
		if p.Kind == kind {
			return true
		}
	}
	return false
}

// allows reports whether any provider may supply this kind of observation.
func (c *Collector) allows(kind string) bool {
	for _, p := range c.config.Providers {
		for _, k := range p.Allowed {
			if k == kind {
				return true
			}
		}
	}
	return false
}

// clockBinding names the binding the source map asks for, or "none".
func (c *Collector) clockBinding() string {
	for _, p := range c.config.Providers {
		if p.ClockBinding != "" {
			return p.ClockBinding
		}
	}
	return "none"
}
