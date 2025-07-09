[
    [.buses[] | select(.kind | contains($BUSKIND)) | .members[] ]
    | group_by(.name)[]
    | {
        name: .[0].name,
        occurrences: [.[].occurrences] | add,
        addresses:
            [.[].addresses | to_entries[]] | group_by(.key)
            | map({key: .[0].key, value: [.[].value] | add})
            | from_entries
    }
]
| sort_by(.occurrences)
