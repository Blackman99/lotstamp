// Package pkgdb reads distro package databases (read-only) and compares their versions.
package pkgdb

import (
	"strings"
)

// CompareDeb compares two Debian package versions following deb-version(7):
// [epoch:]upstream[-revision], with '~' sorting before everything, even the end of a part.
func CompareDeb(a, b string) int {
	ea, ua, ra := splitDeb(a)
	eb, ub, rb := splitDeb(b)
	if c := cmpNum(ea, eb); c != 0 {
		return c
	}
	if c := cmpPart(ua, ub); c != 0 {
		return c
	}
	return cmpPart(ra, rb)
}

func splitDeb(v string) (epoch, up, rev string) {
	epoch = "0"
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, v = v[:i], v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func order(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return int(c)
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func cmpPart(a, b string) int {
	for a != "" || b != "" {
		// non-digit prefix
		for (a != "" && !isDigit(a[0])) || (b != "" && !isDigit(b[0])) {
			var ac, bc int
			if a != "" && !isDigit(a[0]) {
				ac = order(a[0])
			}
			if b != "" && !isDigit(b[0]) {
				bc = order(b[0])
			}
			if ac != bc {
				if ac < bc {
					return -1
				}
				return 1
			}
			if a != "" && !isDigit(a[0]) {
				a = a[1:]
			}
			if b != "" && !isDigit(b[0]) {
				b = b[1:]
			}
		}
		var na, nb string
		for a != "" && isDigit(a[0]) {
			na, a = na+a[:1], a[1:]
		}
		for b != "" && isDigit(b[0]) {
			nb, b = nb+b[:1], b[1:]
		}
		if c := cmpNum(na, nb); c != 0 {
			return c
		}
	}
	return 0
}

func cmpNum(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}
