## Payload Processing

Payloads can grow in size and complexity, so it makes sense to use proper tooling to interact with them,
specially when:

- We need to modify logic into multiple of them.
- We need to reason about failures.
- We want to generate then by using logic rules that ensures we cover all the possible scenarios.

### Tooling

#### JQ

For performing a fast analysis of the output `JSON` payloads, `jq` is a great tool that lets us filter the
data and use its structure for processing it. Multiple example filters and their descriptions can be found
at `jq_filters` folder.

A great example of a handy `jq` filter for analyzing a `simulator` output is:

```
jq --compact-output ".results[0] | (.exp_proxysql_state? - .act_proxysql_state?) + (.act_proxysql_state? - .exp_proxysql_state?) | .[]" simulator_output.json
```

This filter will allows us to see the differences found between members `exp_proxysql_state` and
`act_proxysql_state` from the result array member specified at `results[0]`. In this case, the first result.
Variations of this filter can be used for checking where are the missing members, for example, are we missing
a server at `act_proxysql_state`?

```
jq --compact-output ".results[0] | (.act_proxysql_state? - .exp_proxysql_state?) | .[]" simulator_output.json
```

#### NodeJS

We shouldn't forget that by definition `JSON` is just valid Javascript, so, the most powerful tool for
exploring/prototyping/building payloads, is `nodejs` itself. If `jq` doesn't seems enough for a particular
task, or if `filters` are getting too complex and harder to reason about, resorting to `node` can be a great
alternative. In the `node` folder, there is a minimal application which can serve as a template for modifying.
