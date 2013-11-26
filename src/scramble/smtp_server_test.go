package scramble

import "testing"

func TestMimeHeaderDecode(t *testing.T) {
	pairs := [...][2]string{
		{"=?ISO-2022-JP?B?GyRCIVo9dztSOWJAOCVBJWMbKEI=?=", "【女子高生チャ"},
		{"=?iso-2022-Jp?b?GyRCIVo9dztSOWJAOCVBJWMbKEI=?=", "【女子高生チャ"},
		{"=?utf-8?b?V2l0aGRyYXcgY29uZmlybWF0aW9u?=", "Withdraw confirmation"}}
	for _, pair := range pairs {
		in, out := pair[0], pair[1]
		if x := mimeHeaderDecode(in); x != out {
			t.Errorf("mimeHeaderDecode(%s) = %s, should be %s", in, x, out)
		}
	}
}
