package sensitiveword

var _ SensitiveFilter = (*SensitiveFilterStruct)(nil)

// 敏感词过滤
type SensitiveFilter interface {
	Filter(input string) (string, error)
}

// 实现敏感词过滤接口

type SensitiveFilterStruct struct {
}

func NewSensitiveFilterStruct() SensitiveFilter {
	return &SensitiveFilterStruct{}
}

func (s *SensitiveFilterStruct) Filter(input string) (string, error) {
	err := GetFilter().Apply(input)
	if err != nil {
		return "", err
	}
	return input, nil
}
