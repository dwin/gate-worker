/** Base class for failures talking to the GitHub API. */
export class GitHubError extends Error {
  override name = "GitHubError";
}

/** The repository does not exist or the App's installation cannot access it. */
export class RepositoryNotFoundError extends GitHubError {
  override name = "RepositoryNotFoundError";
  constructor(repository: string) {
    super(`repository not found or not accessible: ${repository}`);
  }
}

/** No installation of the App exists for the owner (organization or user). */
export class InstallationNotFoundError extends GitHubError {
  override name = "InstallationNotFoundError";
  constructor(owner: string) {
    super(`installation not found for owner: ${owner}`);
  }
}

/** The requested path does not exist or is a directory. */
export class FileNotFoundError extends GitHubError {
  override name = "FileNotFoundError";
  constructor(location: string) {
    super(`file not found: ${location}`);
  }
}

/** Any other non-success response from GitHub. */
export class GitHubApiError extends GitHubError {
  override name = "GitHubApiError";
  readonly status: number;

  constructor(status: number, message: string) {
    super(`GitHub API error (status ${String(status)}): ${message}`);
    this.status = status;
  }
}
