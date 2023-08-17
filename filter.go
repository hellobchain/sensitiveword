package sensitiveword

import (
	"bytes"
	"sync"

	"github.com/hellobchain/sensitivewordfilter"
)

// Filter create sensitive chars filter from slice
type Filter struct {
	filterLock    sync.Mutex
	filterManager *sensitivewordfilter.SensitivewordManager
}

type sensitiveWordConf struct {
	Store                  string
	Path                   string
	SensitiveFileName      string
	ExcludedSymbolFileName string
	Words                  []string
}

func NewSensitiveWordFilterFromPath(store string, path string, sensitiveFileName string, excludedSymbolFileName string, words []string) *Filter {
	return newSensitiveWordFilterFromPath(&sensitiveWordConf{
		Store:                  store,
		SensitiveFileName:      sensitiveFileName,
		ExcludedSymbolFileName: excludedSymbolFileName,
		Words:                  words,
	})
}

func GetFilter() *Filter {
	return globalFilter
}

// Apply returns an error if the message contains sensitive word
func (nf *Filter) Apply(message string) error {
	valueBuf := bytes.NewBufferString(message)
	excludes, err := nf.filterManager.ExcludesStore().ReadAll()
	if err != nil {
		return err
	}
	logger.Debug("exclude symbols", excludes)
	isExistSensitiveWord := nf.filterManager.Filter().IsExistReader(valueBuf, stringArrayToRuneArray(excludes)...)
	if isExistSensitiveWord {
		return errSensitiveWord
	}
	return nil
}
