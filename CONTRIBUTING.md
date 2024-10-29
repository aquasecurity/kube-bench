Thank you for taking an interest in contributing to kube-bench !

## Contributing, bug reporting, openning issues and starting discussions

### Issues

- Feel free to open an issue for any reason as long as you make it clear if the issue is about a bug/feature/question/comment.
- Please spend some time giving due diligence to the issue tracker. Your issue might be a duplicate. If it is, please add your comment to the existing issue.
- Remember, users might be searching for your issue in the future. So please give it a meaningful title to help others.
- The issue should clearly explain the reason for opening the proposal if you have any, along with any relevant technical information.
- For questions and bug reports, please include the following information:
  - version of kube-bench you are running (from kube-bench version) along with the command line options you are using.
  - version of Kubernetes you are running (from kubectl version or oc version for Openshift).
  - Verbose log output, by setting the `-v 3` command line option.

### Bugs

If you think you have found a bug please follow the instructions below.

- Open a [new bug](https://github.com/aquasecurity/kube-bench/issues/new?assignees=&labels=&template=bug_report.md) if a duplicate doesn't already exist.
- Make sure to give as much information as possible in the following questions
  - Overview
  - How did you run kube-bench?
  - What happened?
  - What did you expect to happen
  - Environment
  - Running processes
  - Configuration files
  - Anything else you would like to add
- Set `-v 3` command line option and save the log output. Please paste this into your issue.


### Features

We also use the GitHub discussions to track feature requests. If you have an idea to make kube-bench even more awesome follow the steps below.

- Open a [new discussion](https://github.com/aquasecurity/kube-bench/discussions/new?category_id=19113743) if a duplicate doesn't already exist.
- Remember users might be searching for your discussion in the future, so please give it a meaningful title to helps others.
- Clearly define the use case, using concrete examples. For example, I type `this` and kube-bench does `that`.
- If you would like to include a technical design for your feature please feel free to do so.

### Questions

We also use the GitHub discussions to Q&A.

- Open a [new discussion](https://github.com/aquasecurity/kube-bench/discussions/new) if a duplicate doesn't already exist.
- Remember users might be searching for your discussion in the future, so please give it a meaningful title to helps others.


### Pull Requests

We welcome pull requests!
- Every Pull Request should have an associated Issue, unless you are fixing a trivial documentation issue.
- We will not accept changes to LICENSE, NOTICE or CONTRIBUTING from outside the Aqua Security team. Please raise an Issue if you believe there is a problem with any of these files. 
- Your PR is more likely to be accepted if it focuses on just one change.
- Describe what the PR does. There's no convention enforced, but please try to be concise and descriptive. Treat the PR description as a commit message. Titles that start with "fix"/"add"/"improve"/"remove" are good examples.
- Please add the associated Issue in the PR description.
- Please include a comment with the results before and after your change.
- There's no need to add or tag reviewers.
- If a reviewer commented on your code or asked for changes, please remember to mark the discussion as resolved after you address it. PRs with unresolved issues should not be merged (even if the comment is unclear or requires no action from your side).
- Please include a comment with the results before and after your change.
- Your PR is more likely to be accepted if it includes tests (We have not historically been very strict about tests, but we would like to improve this!).
- You're welcome to submit a draft PR if you would like early feedback on an idea or an approach.
- Happy coding!

## Testing locally with kind

Our makefile contains targets to test your current version of kube-bench inside a [Kind](https://kind.sigs.k8s.io/) cluster. This can be very handy if you don't want to run a real Kubernetes cluster for development purposes.

First, you'll need to create the cluster using `make kind-test-cluster` this will create a new cluster if it cannot be found on your machine. By default, the cluster is named `kube-bench` but you can change the name by using the environment variable `KIND_PROFILE`.

*If kind cannot be found on your system the target will try to install it using `go get`*

Next, you'll have to build the kube-bench docker image using `make build-docker`, then we will be able to push the docker image to the cluster using `make kind-push`.

Finally, we can use the `make kind-run` target to run the current version of kube-bench in the cluster and follow the logs of pods created. (Ctrl+C to exit)

Every time you want to test a change, you'll need to rebuild the docker image and push it to cluster before running it again. ( `make build-docker kind-push kind-run` )

To run the STIG tests locally execute the following: `make build-docker kind-push kind-run-stig`
