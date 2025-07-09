.peripherals
| [.[] | select(.name | contains($PKIND))]
| map({name, occurrences})
| sort_by(.occurrences)
