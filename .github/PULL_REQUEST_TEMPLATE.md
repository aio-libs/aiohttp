<!-- Thank you for your contribution! -->

## What do these changes do?

<!-- Please give a short brief about these changes. -->

## Are there changes in behavior for the user?

<!-- Outline any notable behaviour for the end users. -->

## Is it a substantial burden for the maintainers to support this?

<!--
Stop right there! Pause. Just for a minute... Can you think of anything
obvious that would complicate the ongoing development of this project?

Try to consider if you'd be able to maintain it throughout the next
5 years. Does it seem viable? Tell us your thoughts! We'd very much
love to hear what the consequences of merging this patch might be...

This will help us assess if your change is something we'd want to
entertain early in the review process. Thank you in advance!
-->

## Related issue number

<!-- Are there any issues opened that will be resolved by merging this change? -->
<!-- Remember to prefix with 'Fixes' if it should close the issue (e.g. 'Fixes #123'). -->

## Checklist

- [ ] I think the code is well written
- [ ] Unit tests for the changes exist
- [ ] Documentation reflects the changes
- [ ] If you provide code modification, please add yourself to `CONTRIBUTORS.txt`
  * The format is &lt;Name&gt; &lt;Surname&gt;.
  * Please keep alphabetical order, the file is sorted by names.
- [ ] Add a new news fragment into the `CHANGES/` folder
  * name it `<issue_or_pr_num>.<type>.rst` (e.g. `588.bugfix.rst`)
  * if you don't have an issue number, change it to the pull request
    number after creating the PR
    * `.bugfix`: A bug fix for something the maintainers deemed an
      improper undesired behavior that got corrected to match
      pre-agreed expectations.
    * `.feature`: A new behavior, public APIs. That sort of stuff.
    * `.deprecation`: A declaration of future API removals and breaking
      changes in behavior.
    * `.breaking`: When something public is removed in a breaking way.
      Could be deprecated in an earlier release.
    * `.doc`: Notable updates to the documentation structure or build
      process.
    * `.packaging`: Notes for downstreams about unobvious side effects
      and tooling. Changes in the test invocation considerations and
      runtime assumptions.
    * `.contrib`: Stuff that affects the contributor experience. e.g.
      Running tests, building the docs, setting up the development
      environment.
    * `.misc`: Changes that are hard to assign to any of the above
      categories.
  * Make sure to use full sentences with correct case and punctuation,
    for example:
    ```rst
    Fixed issue with non-ascii contents in doctest text files
    -- by :user:`contributor-gh-handle`.
    ```

    Use the past tense or the present tense a non-imperative mood,
    referring to what's changed compared to the last released version
    of this project.
