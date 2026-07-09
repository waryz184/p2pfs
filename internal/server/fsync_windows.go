//go:build windows

package server

// fsyncDir est un no-op sur Windows : contrairement à POSIX, on ne peut pas
// ouvrir un répertoire comme descripteur syncable (os.Open+Sync renvoie
// "Access is denied"). Le rename est déjà atomique côté NTFS ; seule la
// durabilité de l'entrée de répertoire après crash n'est pas garantie ici.
// Sans impact en production : la cible de déploiement est un conteneur Linux
// (voir Dockerfile), où fsync_unix.go s'applique.
func fsyncDir(dir string) error {
	return nil
}
