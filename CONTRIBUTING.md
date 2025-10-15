# Contribution Guidelines

Thank you for considering contributing to our project! To maintain a high standard of quality and consistency, please follow these guidelines when making contributions.

Here is a short checklist to consider when preparing a Pull Request:
- Check the commit history of the feature branch and consider rebasing/squashing bugfixing commits.
- Check license and copyright header and update the year if needed.
- Check the SonarCloud report and try to fix issues and improve coverage rating of new code.
- Does the PR affect any other repository? If so, please open an issue in the affected repo and link it to the PR.
- Check if PR closes any open issue and link the issue in the PR description.
- Check if the documentation need to be updated or extended.

## 1. Commit Messages

Please follow the Conventional Changelog format for commit messages. This helps in generating readable and consistent changelogs. Here are the key points:

- **Format**: `<type>(<scope>): <subject>`
- **Types**: Use one of the following types:
  - `feat`: A new feature
  - `fix`: A bug fix
  - `docs`: Documentation only changes
  - `style`: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
  - `refactor`: A code change that neither fixes a bug nor adds a feature
  - `perf`: A code change that improves performance
  - `test`: Adding missing or correcting existing tests
  - `chore`: Changes to the build process or auxiliary tools and libraries such as documentation generation
- **Scope**: The scope could be anything specifying the place of the commit change (e.g., `core`, `ui`, `docs`).
- **Subject**: Use the imperative, present tense (e.g., "change" not "changed" nor "changes").

Simple example:
```
feat: add gta_seal_data for profile xy
```

## 2. Code Style

This project enforces consistent code formatting using `clang-format`, with rules defined in the [`.clang-format`](.clang-format) file located at the root of the repository.

To ensure your contributions adhere to the project's style guidelines:
- Manual formatting: Run the following command to apply formatting to the codebase:
  ```
  ninja -C <build_dir> clang-format
  ```
- Automatic formatting: A Git pre-commit hook is provided to automatically format your code before each commit. To enable it for this repository, run the following command from the repository root:
  ```
  git config --local core.hooksPath .hooks
  ```

### Examples of code style rules

- Use four (4) spaces to indent the code.
- No white-spaces at the end of a line.
- Use macros instead of magic numbers.
- Use C-style comments as shown in the following examples (don't use double-slash `//`):
```
/* This comment fits in one line */
```
```
/*
 * This is a multi-line
 * comment.
 */
``` 
- When making comparisons, always place constant values on the left side, e.g.
```
if (GTA_ERROR_HANDLE_INVALID == ret) {
    /* handle invalid*/
}
```
- Format of conditions:
```
if (condition1) {
    do_something();
} else if (condition2) {
    do_something();
} else {
    do_something();
}
```

## 3. Pull Requests

- Fork the repository and create your branch from `main`.
- Try to maintain a clean commit history. Ensure each commit is focused on a single change or feature.  Use `git rebase -i` to squash e.g. bugfix commits.
- Ensure the PR description clearly describes the problem and solution.
- Include relevant issue numbers in the PR description (e.g., `Fixes #123`).

## 4. Testing

- Write tests for your code.
- Ensure all tests pass.
- Try to increase the coverage rating.

## 5. Documentation

- Update the documentation to reflect your changes.
- Ensure that any new features or changes are well-documented.