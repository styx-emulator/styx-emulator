

[
    [
        .buses[]
        | select(.kind | contains($BUSKIND))
        | .members[] | {name, occurrences}
    ]
    | group_by(.name)[]
    | {name: .[0].name, occurrences: [.[].occurrences] | add}
]
| sort_by(.occurrences)
