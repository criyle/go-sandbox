package main

import "fmt"

type arrayFlags []string

func (f *arrayFlags) String() string {
	return fmt.Sprint([]string(*f))
}

func (f *arrayFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}
