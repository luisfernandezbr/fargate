package docker

import (
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jpignata/fargate/console"
)

const timestampFormat = "20060102150405"

func GenerateTag() string {
	return time.Now().UTC().Format(timestampFormat)
}

type Repository struct {
	Uri string
}

func NewRepository(repositoryUri string) Repository {
	return Repository{
		Uri: repositoryUri,
	}
}

func (repository *Repository) Login(username, password string) {
	console.Debug("Logging into Docker repository [%s]", repository.Uri)
	console.Shell("docker login --username %s --password ******* %s", username, repository.Uri)

	cmd := exec.Command("docker", "login", "--username", username, "--password", password, repository.Uri)

	if console.Verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		console.ErrorExit(err, "Couldn't login to Docker repository [%s]", repository.Uri)
	}

	if err := cmd.Wait(); err != nil {
		console.IssueExit("Couldn't login to Docker repository [%s]", repository.Uri)
	}
}

func (repository *Repository) Build(tag, dockerfile string) {
	console.Debug("Building Docker image [%s] dockerfile [%s]", repository.UriFor(tag), dockerfile)

	args := []string{"build", "--tag", repository.Uri + ":" + tag}

	if dockerfile != "" {
		args = append(args, "--file", dockerfile)
	}

	args = append(args, ".")

	console.Shell("docker %s", strings.Join(args, " "))

	cmd := exec.Command("docker", args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		console.ErrorExit(err, "Couldn't build Docker image [%s]", repository.UriFor(tag))
	}

	if err := cmd.Wait(); err != nil {
		console.IssueExit("Couldn't build Docker image [%s]", repository.Uri)
	}
}

func (repository *Repository) Push(tag string) {
	console.Debug("Pushing Docker image [%s]", repository.UriFor(tag))
	console.Shell("docker push %s .", repository.UriFor(tag))

	cmd := exec.Command("docker", "push", repository.UriFor(tag))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		console.ErrorExit(err, "Couldn't push Docker image [%s]", repository.UriFor(tag))
	}

	if err := cmd.Wait(); err != nil {
		console.IssueExit("Couldn't push Docker image [%s]", repository.UriFor(tag))
	}
}

func (repository *Repository) UriFor(tag string) string {
	return repository.Uri + ":" + tag
}
