package sensitiveword

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hellobchain/sensitivewordfilter"
	"github.com/hellobchain/sensitivewordfilter/filter/newdfa"
	"github.com/hellobchain/sensitivewordfilter/store"
	"github.com/hellobchain/sensitivewordfilter/store/leveldb"
	"github.com/hellobchain/sensitivewordfilter/store/memory"
	"github.com/hellobchain/wswlog/wlogging"
)

var logger = wlogging.MustGetLoggerWithoutName()
var globalFilter *Filter

// ErrSensitiveWord is returned by errors which are caused by sensitive word
var errSensitiveWord = errors.New("there are sensitive words")

// QuerySensitiveWord 查询敏感词
func QuerySensitiveWord() ([]string, error) {
	globalFilter.filterLock.Lock()
	defer globalFilter.filterLock.Unlock()
	return globalFilter.filterManager.SensitiveWordStore().ReadAll()
}

// AddSensitiveWord 批量增加敏感词
func AddSensitiveWord(text []string) error {
	globalFilter.filterLock.Lock()
	defer globalFilter.filterLock.Unlock()
	globalFilter.filterManager.Filter().Add(text...)
	return globalFilter.filterManager.SensitiveWordStore().Write(text...)
}

// SetSensitiveWord 重置敏感词
func SetSensitiveWord(text []string) error {
	globalFilter.filterLock.Lock()
	defer globalFilter.filterLock.Unlock()
	allSensitiveword, err := globalFilter.filterManager.SensitiveWordStore().ReadAll()
	if err != nil {
		logger.Errorf("read sensitive words failed %v", err)
		return err
	}
	globalFilter.filterManager.Filter().Remove(allSensitiveword...)
	globalFilter.filterManager.Filter().Add(text...)
	err = globalFilter.filterManager.SensitiveWordStore().Remove(allSensitiveword...)
	if err != nil {
		logger.Errorf("remove sensitive word failed %v", err)
		return err
	}
	err = globalFilter.filterManager.SensitiveWordStore().Write(text...)
	if err != nil {
		logger.Errorf("set sensitive word failed %v", err)
		return err
	}
	return nil
}

func QueryExcludedSymbol() ([]byte, error) {
	globalFilter.filterLock.Lock()
	defer globalFilter.filterLock.Unlock()
	excludes, err := globalFilter.filterManager.ExcludesStore().ReadAll()
	if err != nil {
		logger.Errorf("query excludes failed %v", err)
		return nil, err
	}
	return []byte(strings.Join(excludes, "|")), nil

}

func AddExcludedSymbol(text string) error {
	globalFilter.filterLock.Lock()
	defer globalFilter.filterLock.Unlock()
	return globalFilter.filterManager.ExcludesStore().Write(text)
}

func SetExcludedSymbol(text string) error {
	globalFilter.filterLock.Lock()
	defer globalFilter.filterLock.Unlock()
	allExcludes, err := globalFilter.filterManager.ExcludesStore().ReadAll()
	if err != nil {
		logger.Errorf("read exclude symbols failed %v", err)
		return err
	}
	err = globalFilter.filterManager.ExcludesStore().Remove(allExcludes...)
	if err != nil {
		logger.Errorf("remove exclude symbols failed %v", err)
		return err
	}
	err = globalFilter.filterManager.ExcludesStore().Write(text)
	if err != nil {
		logger.Errorf("set exclude symbols failed %v", err)
		return err
	}
	return nil
}

func dealwithOldSensitivewords(sensitiveWordConf *sensitiveWordConf) ([]string, []string, string, string, error) {
	var sensitivewords, excludes []string
	sensitivewordPath := filepath.Join(sensitiveWordConf.Path, sensitiveWordConf.SensitiveFileName)
	logger.Info("sensitive word path", sensitivewordPath)
	if s, err := os.Stat(sensitivewordPath); err == nil {
		if !s.IsDir() { // 文件
			ret, err := ioutil.ReadFile(sensitivewordPath)
			if err != nil {
				return nil, nil, "", "", err
			}
			sensitivewords = strings.Split(string(ret), "|")
			err = os.Remove(sensitivewordPath)
			if err != nil {
				logger.Warnf("remove path %s %v", sensitivewordPath, err)
			}
		}
	} else {
		err = os.MkdirAll(sensitivewordPath, os.ModePerm)
		if err != nil {
			logger.Warnf("mkdir path %s %v", sensitivewordPath, err)
		}
	}
	excludePath := filepath.Join(sensitiveWordConf.Path, sensitiveWordConf.ExcludedSymbolFileName)
	logger.Info("exclude symbols path", excludePath)
	if s, err := os.Stat(sensitivewordPath); err == nil {
		if !s.IsDir() { // 文件
			ret, err := ioutil.ReadFile(sensitivewordPath)
			if err != nil {
				return nil, nil, "", "", err
			}
			excludes = strings.Split(string(ret), "|")
			err = os.Remove(excludePath)
			if err != nil {
				logger.Warnf("remove path %s %v", excludePath, err)
			}
		}
	} else {
		err = os.MkdirAll(excludePath, os.ModePerm)
		if err != nil {
			logger.Warnf("mkdir path %s %v", excludePath, err)
		}
	}
	return sensitivewords, excludes, sensitivewordPath, excludePath, nil
}

var initOnce sync.Once

func newSensitiveWordFilterFromPath(sensitiveWordConf *sensitiveWordConf) *Filter {
	initOnce.Do(func() {
		sensitivewords, excludes, sensitivewordPath, excludePath, err := dealwithOldSensitivewords(sensitiveWordConf)
		if err != nil {
			panic(err)
		}
		var sensitivewordStore store.SensitivewordStore
		var excludeStore store.SensitivewordStore
		switch strings.ToLower(sensitiveWordConf.Store) {
		case "leveldb":
			sensitivewordStore, err = leveldb.NewLevelDbStore(leveldb.LevelDbConfig{
				Path: sensitivewordPath,
			})
			if err != nil {
				panic(err)
			}
			excludeStore, err = leveldb.NewLevelDbStore(leveldb.LevelDbConfig{
				Path: excludePath,
			})
			if err != nil {
				panic(err)
			}
			err = sensitivewordStore.Write(sensitivewords...)
			if err != nil {
				panic(err)
			}
			err = excludeStore.Write(excludes...)
			if err != nil {
				panic(err)
			}
		case "memory", "":
			sensitivewordStore, err = memory.NewMemoryStore(memory.MemoryConfig{
				DataSource: sensitivewords,
			})
			if err != nil {
				panic(err)
			}
			excludeStore, err = memory.NewMemoryStore(memory.MemoryConfig{
				DataSource: excludes,
			})
			if err != nil {
				panic(err)
			}
		}
		allSensitivewords, err := sensitivewordStore.ReadAll()
		if err != nil {
			panic(err)
		}
		filter := newdfa.NewNodeFilter(allSensitivewords)
		if err != nil {
			panic(err)
		}
		globalFilter = &Filter{
			filterManager: sensitivewordfilter.NewSensitivewordManager(sensitivewordStore, excludeStore, filter),
		}
	})
	return globalFilter
}

func stringArrayToRuneArray(strs []string) []rune {
	var ret []rune
	for _, str := range strs {
		ret = append(ret, []rune(str)...)
	}
	return ret
}
