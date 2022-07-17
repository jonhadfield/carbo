package helpers

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
)

func ReadFileBytes(path string) (content []byte, err error) {
	funcName := GetFunctionName()

	logrus.Debugf("%s | reading %s", funcName, path)

	if _, err = os.Stat(path); err != nil {
		err = fmt.Errorf("%s - %w", funcName, err)

		return
	}

	content, err = ioutil.ReadFile(path)
	if err != nil {
		err = fmt.Errorf("%s - %w", funcName, err)

		return
	}

	return
}

func ReadTextFile(path string) (content string, err error) {
	funcName := GetFunctionName()

	b, err := ReadFileBytes(path)
	if err != nil {
		err = fmt.Errorf("%s - %w", funcName, err)
	}

	return string(b), err
}
