//go:build !windows

package server

import "os"

// fsyncDir force l'écriture de l'entrée de répertoire (rend le rename durable
// après un crash). Sur POSIX, un répertoire ouvert comme fichier est syncable.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
