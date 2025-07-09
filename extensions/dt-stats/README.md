# Device Tree Statistics Aggregator

A simple cli tool to gather statistics about commonly used peripherals (on and off die) from collections of devicetrees.
Used to decide where to focus support efforts.

## Usage

Invoking the `dt-stats` command requires at a minimum one argument: a directory to be recursively searched for .dts and .dtb files.
```bash
dt-stats ./my/dir/of/trees/
```

To prevent having to run dt-stats multiple times, it is reccomended to pipe its stdout into a .json file.
The json can be used to generate meaningful statistics later via jq.

To ignore text-based device tree __syntax__ (dts) files, add the `--no-dts` flag. A complimentary `--no-dtb` flag is also provided ignoring compiled/flattened device tree __binary__ (dtb) files.

Any number of `--isystem /path/to/sys/include/dir` flags can be provided which are directly passed to the c preprocessor as many dts files use c-style includes. Similarly, any number of `--include /path/to/normal/include` flags can also be passed.

Dts files from the Zephyr project include files from many locations in their source tree, some spread across different repos.
To generate statistics from Zephyr, the `--zephyr-proj-dir /path/to/zeph/dir` flag has been provided for convenience.
Including this flag will simply append a number of system include paths to those already specified by --isystem.
This is __not__ a path to the main `zephyrproject-rtos/zephyr` repo, rather it is the path to a repo containing the whole Zephyr project.
This includes the main zephyr repo as well as a number of HAL and utility repos.
This can be easily generated using their bespoke tool `west` by running the following script (where the zephyrproject dir is the one to be specified in this flag).
```bash
west init -m https://github.com/zephyrproject-rtos/zephyr --mr main zephyrproject
cd zephyrproject
west update
```

For a run on the linux source code, only the /linux/include isystem dir and linux/arch/ need to be specified:
```bash
dt-stats --isystem ./linux/include/ ./linux/arch/
```

## Processing

dt-stats generates raw data, which needs to be refined by jq (or any other json parser) in order to produce meaningful statistics.

The raw data follows the following format:
```jsonc
{
    "meta" : {
        //Meta information about the run
    },
    "buses" :
    // Buses contains information about external devices that are located on buses that leave the soc.
    // This might be something like a little i2c temperature sensor or accelerometer that the chip is connected to.
    [
        {
            "kind" : "The specific bus that the following members are connected to."
            // Note that bus kind is device-specifice, so an st i2c bus will have a different kind than a qualcom i2c bus.
            "members" : [
                {
                    // Example:
                    "name": "temperature sensor",
                    "occurrences": 3, // how many times "temperature sensor" occurred on this bus. May occurr more times on other buses.
                    // The addresses where this device was found on the bus, using the buses addressing scheme. May be empty.
                    "addresses": {
                        "0x50": 2,
                        "0x51": 1
                    }
                },
                // More members
            ]
        },
        // ...
    ],
    "peripherals":
    // Peripherals is an array of data that relates to on-soc peripherals like a mmio i2c interface.
    [
        {
            "name": "qcom,i2c-qup-v2.2.1", // Peripheral name (or name of driver used to interface with peripheral)
            "occurrences": 777, // How many times across all trees this peripheral was found. Could be counted multiple times per soc.
            "addrs": { // Which mmio addresses this peripheral was found at.
                "0x78B8000" : 72,
                "0xC178000": 18,
                // More addrs
            }
        }
        // More peripherals
    ]
}
```

So, if results are stored in linux.json, this jq query could retrieve metadata:
```bash
cat linux.json | jq ".meta"

```

### Included jq scripts

This repo contains a few jq scripts that might be useful.

#### Bus member counts
Path: ./scripts/bus_member_count.jq

Description: First, filters the buses data down to only buses who have kind containing BUSKIND. Then for each member, totals its occurrences across all remaining buses. Useful to find, for example, the most common i2c devices.

Invocation:
```bash
cat linux | jq -f ./scripts/bus_member_count.jq --arg BUSKIND "i2c"
```

#### Bus member counts with addresses
Path: ./scripts/bus_member_count_addrs.jq

Description: Same as previous but also displays addresses of found members.

Invocation:
```bash
cat linux | jq -f ./scripts/bus_member_count_addrs.jq --arg BUSKIND "i2c"
```

#### Peripheral counts
Path: ./scripts/periph_count.jq

Description: Finds the counts of each type of peripheral whose name contains PKIND.

Invocation:
```bash
cat linux | jq -f ./scripts/periph_count.jq --arg PKIND "i2c"
```

#### Peripheral counts with addresses
Path: ./scripts/periph_count_addrs.jq

Description: Same as previous but also displays all addresses peripherals are found at.

Invocation:
```bash
cat linux | jq -f ./scripts/periph_count_addrs.jq --arg PKIND "i2c"
```
