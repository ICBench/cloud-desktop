package manager

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

var noEscape [256]bool

func init() {
	for i := 0; i < len(noEscape); i++ {
		noEscape[i] = (i >= 'A' && i <= 'Z') ||
			(i >= 'a' && i <= 'z') ||
			(i >= '0' && i <= '9') ||
			i == '-' ||
			i == '.' ||
			i == '_' ||
			i == '~'
	}
}

// type hashCRC64 struct {
// 	init uint64
// 	crc  uint64
// 	tab  *crc64.Table
// }

// func (d *hashCRC64) Size() int {
// 	return crc64.Size
// }

// func (d *hashCRC64) BlockSize() int {
// 	return 1
// }

// func (d *hashCRC64) Reset() {
// 	d.crc = d.init
// }

// func (d *hashCRC64) Write(p []byte) (n int, err error) {
// 	d.crc = crc64.Update(d.crc, d.tab, p)
// 	return len(p), nil
// }

// func (d *hashCRC64) Sum64() uint64 {
// 	return d.crc
// }

// func (d *hashCRC64) Sum(in []byte) []byte {
// 	s := d.Sum64()
// 	return append(in, byte(s>>56), byte(s>>48), byte(s>>40), byte(s>>32), byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
// }

// func NewCRC64(init uint64) hash.Hash64 {
// 	return &hashCRC64{
// 		init: init,
// 		crc:  init,
// 		tab:  crc64.MakeTable(crc64.ECMA),
// 	}
// }

func escapePath(path string, encodeSep bool) string {
	var buf bytes.Buffer
	for i := 0; i < len(path); i++ {
		c := path[i]
		if noEscape[c] || (c == '/' && !encodeSep) {
			buf.WriteByte(c)
		} else {
			fmt.Fprintf(&buf, "%%%02X", c)
		}
	}
	return buf.String()
}

func ParseRange(s string) (r *HTTPRange, err error) {
	const preamble = "bytes="
	if !strings.HasPrefix(s, preamble) {
		return nil, errors.New("range: header invalid: doesn't start with " + preamble)
	}
	s = s[len(preamble):]
	if strings.ContainsRune(s, ',') {
		return nil, errors.New("range: header invalid: contains multiple ranges which isn't supported")
	}
	dash := strings.IndexRune(s, '-')
	if dash < 0 {
		return nil, errors.New("range: header invalid: contains no '-'")
	}
	start, end := strings.TrimSpace(s[:dash]), strings.TrimSpace(s[dash+1:])
	o := HTTPRange{Offset: 0, Count: 0}
	if start != "" {
		o.Offset, err = strconv.ParseInt(start, 10, 64)
		if err != nil || o.Offset < 0 {
			return nil, errors.New("range: header invalid: bad start")
		}
	}
	if end != "" {
		e, err := strconv.ParseInt(end, 10, 64)
		if err != nil || e < 0 {
			return nil, errors.New("range: header invalid: bad end")
		}
		o.Count = e - o.Offset + 1
	}
	return &o, nil
}

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return (info != nil && !info.IsDir())
}

func DirExists(dir string) bool {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return false
	}
	return (info != nil && info.IsDir())
}

func EmptyFile(filename string) bool {
	err := os.Truncate(filename, 0)
	return err == nil
}

func seekerLen(s io.Seeker) (int64, error) {
	curOffset, err := s.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}

	endOffset, err := s.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}

	_, err = s.Seek(curOffset, io.SeekStart)
	if err != nil {
		return 0, err
	}

	return endOffset - curOffset, nil
}

func GetReaderLen(r io.Reader) int64 {
	type lenner interface {
		Len() int
	}

	if lr, ok := r.(lenner); ok {
		return int64(lr.Len())
	}

	if s, ok := r.(io.Seeker); ok {
		if l, err := seekerLen(s); err == nil {
			return l
		}
	}

	return -1
}

func copyRequest(dst, src interface{}) {
	dstval := reflect.ValueOf(dst)
	if !dstval.IsValid() {
		panic("Copy dst cannot be nil")
	}

	rcopy(dstval, reflect.ValueOf(src), true)
}

func rcopy(dst, src reflect.Value, root bool) {
	if !src.IsValid() {
		return
	}

	switch src.Kind() {
	case reflect.Ptr:
		if _, ok := src.Interface().(io.Reader); ok {
			if dst.Kind() == reflect.Ptr && dst.Elem().CanSet() {
				dst.Elem().Set(src)
			} else if dst.CanSet() {
				dst.Set(src)
			}
		} else {
			e := src.Type().Elem()
			if dst.CanSet() && !src.IsNil() {
				if _, ok := src.Interface().(*time.Time); !ok {
					if dst.Kind() == reflect.String {
						dst.SetString(e.String())
					} else {
						dst.Set(reflect.New(e))
					}
				} else {
					tempValue := reflect.New(e)
					tempValue.Elem().Set(src.Elem())
					dst.Set(tempValue)
				}
			}
			if dst.Kind() != reflect.String && src.Elem().IsValid() {
				rcopy(dst.Elem(), src.Elem(), root)
			}
		}
	case reflect.Struct:
		t := dst.Type()
		for i := 0; i < t.NumField(); i++ {
			name := t.Field(i).Name
			srcVal := src.FieldByName(name)
			dstVal := dst.FieldByName(name)
			if srcVal.IsValid() && dstVal.CanSet() {
				rcopy(dstVal, srcVal, false)
			}
		}
	case reflect.Slice:
		if src.IsNil() {
			break
		}

		s := reflect.MakeSlice(src.Type(), src.Len(), src.Cap())
		dst.Set(s)
		for i := 0; i < src.Len(); i++ {
			rcopy(dst.Index(i), src.Index(i), false)
		}
	case reflect.Map:
		if src.IsNil() {
			break
		}

		s := reflect.MakeMap(src.Type())
		dst.Set(s)
		for _, k := range src.MapKeys() {
			v := src.MapIndex(k)
			v2 := reflect.New(v.Type()).Elem()
			rcopy(v2, v, false)
			dst.SetMapIndex(k, v2)
		}
	default:
		if src.Type().AssignableTo(dst.Type()) {
			dst.Set(src)
		}
	}
}
