package main

import "os"

// prepareFile opens file for new process
func prepareFiles(inputFile, outputFile, errorFile string) ([]*os.File, error) {
	var err error
	files := make([]*os.File, 3)
	if inputFile != "" {
		files[0], err = os.OpenFile(inputFile, os.O_RDONLY, 0755)
		if err != nil {
			goto openerror
		}
	}
	if outputFile != "" {
		files[1], err = os.OpenFile(outputFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0755)
		if err != nil {
			goto openerror
		}
	}
	if errorFile != "" {
		files[2], err = os.OpenFile(errorFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0755)
		if err != nil {
			goto openerror
		}
	}
	return files, nil
openerror:
	closeFiles(files)
	return nil, err
}

// closeFiles close all file in the list
func closeFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			f.Close()
		}
	}
}
