Thank you for taking interest in contributing to kube-bench!

## Issues

- Feel free to open issues for any reason as long as you make it clear if this issue is about a bug/feature/question/comment.
- Please spend a small amount of time giving due diligence to the issue tracker. Your issue might be a duplicate. If it is, please add your comment to the existing issue.
- Remember users might be searching for your issue in the future, so please give it a meaningful title to help others.
- The issue should clearly explain the reason for opening, the proposal if you have any relevant technical information.
- For questions and bug reports, please include the following information:
  - a version of kube-bench you are running (from kube-bench version) and the command line options you are using.
  - a version of Kubernetes you are running (from kubectl version or oc version for Openshift).
  - Verbose log output, by setting the `-v 10` command-line option.

## Pull Requests

1. Every Pull Request should have an associated issue unless you are fixing a trivial documentation issue.
1. Your PR is more likely to be accepted if it focuses on just one change.
1. Describe what the PR does. There's no convention enforced, but please try to be concise and descriptive. Treat the PR description as a `commit message`. Titles that starts with "fix"/"add"/"improve"/"remove" are good examples.
1. Please add the associated issue in the PR description.
1. There's no need to add or tag reviewers.
1. If a reviewer commented on your code or asked for changes, please remember to mark the discussion as `resolved` after you address it. PRs with unresolved issues should not be merged (even if the comment is unclear or requires no action from your side).
1. Please include a comment with the results before and after your change.
1. Your PR is more likely to be accepted if it includes tests (We have not historically been very strict about tests, but we would like to improve this!).
