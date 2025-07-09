#!/bin/bash

check_deps() {
    echo "Checking Dependencies"
    case "${SERVE_ENV}" in
    docker) echo ok
        ;;
    local)
        for b in ng node npm envoy emusvc-svc workspace-svc typhunix-server emuregsvc-svc traceapp-svc workspace-svc; do
            printf "  %-20s" "${b}:"
            which "$b" || echo "Not found. Make sure its built or installed in in PATH"
        done
    ;;
    esac
}

start_local() {
    check_deps
    _run_svc() {
        local name=$1;shift
        /bin/ps -C "${name}" > /dev/null || {
            echo "    Starting + ${name} ${*}"
            ${name} "$@" 2>&1 > "${TRACE_WEBAPP_LOGDIR}"/"${name}".log 2>&1
        }
    }
    cd "${TRACE_SRC_DIR}" || exit
    [[ -f ${TRACE_WEBAPP_LOGDIR} ]] || mkdir -p "${TRACE_WEBAPP_LOGDIR}"
    # make build-backend
    # make npm check-proto
    _run_svc envoy -c "${ENVOY_CONFIG}" -l info --log-path "${TRACE_WEBAPP_LOGDIR}"/envoy_info.log &
    _run_svc typhunix-server -i &
    _run_svc emuregsvc-svc &
    _run_svc traceapp-svc &
    _run_svc workspace-svc &
}
kill_all() {
    ps --no-headers \
    -C envoy,typhunix-server,workspace-svc,emuregsvc-svc,traceapp-svc,emusvc-svc | \
    awk '{print $1}' | while read -r pid; do kill "$pid";done
}

if_cmd() {
    for v in "${CMDS[@]}"; do [[ "$v" == "$1" ]] && return 0;done;return 1
}

usage() {
    echo "$(basename "$0") {build | start | stop | status | down | logs | help }"
    echo ""
    echo "   build: Builds required compnents for webapp. In docker mode, this"
    echo "          includes required containers. (build and pull)"
    echo "   start: Starts backend components, runs \"ng serve\" "
    echo "      up: alias for \"build start\" "
    echo "    stop: Stops services (\"docker compose stop\" in docker mode)"
    echo "    down: Stops services (\"docker compose stop\" in docker mode)"
    echo "  status: Display status of the webapp stack's components"
    echo "    logs: tail logs"
    exit 1
}

typeset -i NO_SERVE=0
typeset -i VERBOSE=0
typeset -a CMDS=()
for arg in "$@"; do
    case "${arg}" in
        # options
        no*serve)     NO_SERVE=1;;
        -v)           VERBOSE=1;;
        # commands
        b*)           CMDS+=(BLD);;
        up)           CMDS+=(BLD START);;
        star*)        CMDS+=(START);;
        ngbuild*)     CMDS+=(NGBUILD START);;
        sto*)         CMDS+=(STOP);;
        stat*)        CMDS+=(STATUS);;
        lo*)          CMDS+=(LOGS);;
        d*n)          CMDS+=(DOWN);;
        h*|--h*|-h*)  CMDS+=(HELP);;
    esac
done

(( ${#CMDS[@]} == 0 )) && usage
if_cmd HELP && usage

if_cmd DOWN && {
    if [[ ${SERVE_ENV} == docker ]] ;then
        docker compose -f "${TRACE_SRC_DIR}"/docker-compose.yml down
    else
        docker compose -f "${TRACE_SRC_DIR}"/docker-compose.yml down
        kill_all
    fi
}

if_cmd STOP && {
    if [[ ${SERVE_ENV} == docker ]] ;then
        docker compose -f "${TRACE_SRC_DIR}"/docker-compose.yml stop
    else
        kill_all
    fi
}

if_cmd BLD && {

    make -C "${TRACE_SRC_DIR}" build || {
        echo make -C "${TRACE_SRC_DIR}" failed
        exit 1
    }
}

if_cmd START && {
    configure_webapp.sh
    if [[ ${SERVE_ENV} == docker ]] ;then
        NGBUILD=false
        if_cmd NGBUILD && NGBUILD=true
        if [[ "${NGBUILD}" == true ]];then
            docker compose -f "${TRACE_SRC_DIR}"/docker-compose.yml \
                run -it --rm --entrypoint ng -w /project/extensions/trace-webapp webapp build
        else
            docker compose -f "${TRACE_SRC_DIR}"/docker-compose.yml up -d
            printf "wait for the webapp to come up, then point browser at: "
            printf "%s\n" "http://${ENVOY_URL_HOST}:${WEBAPP_URL_PORT}"
        fi
    else
        # the database is needed for both SERVE_ENV=local and SERVE_ENV=docker
        docker compose -f "${TRACE_SRC_DIR}"/docker-compose.yml up styxdb -d
        start_local
        cd "${TRACE_SRC_DIR}" || exit
        serving=$(pgrep ng)
        if [[ -z "${serving}" ]]; then
            if (( NO_SERVE > 0 ));then
                printf "NO_SERVE=%d - not running ng serve\n" "$NO_SERVE"
            else
                ng serve --port 4200
            fi
        else
            printf "\n    ng serve: "
            /bin/ps --no-header -p "${serving}"
        fi
    fi
}

VERBOSE=0
if_cmd STATUS && {
    if (( VERBOSE > 0 ));then
        # show environment
        echo "Environment:"
        env | grep -E "_SERVER=|_HOST=|SERVE_ENV=" | while read -r x; do echo "    $x";done
        echo
    fi

    if [[ ${SERVE_ENV} == docker ]] ;then
        echo "docker-compose:"
        D="docker compose -f ${TRACE_SRC_DIR}/docker-compose.yml"
        $D ps -a
        printf "\nContainer Processes:\n"
        for id in $(docker ps -q); do
            docker exec "$id" bash -c 'which ps >/dev/null && ps --no-header -o pid,cmd ' | grep -v no-header |\
            while read -r pid cmd ; do
                printf "  %s %s\n" "$pid" "$cmd"
            done
        done
    else
        # Volumes
        if (( VERBOSE > 0 ));then
            printf "\nVolumes\n"
            docker volume ls|grep -E pgdata | pr -t -n
        fi

        # Services
        printf "\nDatabase/Services:\n"
        docker compose -f "${TRACE_SRC_DIR}"/docker-compose.yml ps styxdb \
            --format "{{.Image}}~{{.Ports}}~({{.Status}})" | awk -F"~" '{
             printf("    %-20s %-30s %s\n", $1, $2, $3)
            }'
        for svc in envoy workspace-svc typhunix-server emuregsvc-svc traceapp-svc ; do
            pid=$(/bin/ps --no-header -o pid -C "${svc}")
            if [[ -n "${pid}" ]]; then
                printf "    %-20s %s\n" "${svc}" "${pid}"
            else
                printf "    %-20s %s\n" "${svc}" "---"
            fi
        done

        # Emulations
        mapfile -t emulation_pids < <(pgrep emusvc-svc)
        printf "\nEmulations( %d )\n" ${#emulation_pids[@]}
        for pid in "${emulation_pids[@]}" ; do
            /bin/ps --no-header -p "$pid"
        done | pr -to4
    fi
}

if_cmd LOGS && {
    if [[ ${SERVE_ENV} == docker ]] ;then
        docker compose -f "${TRACE_SRC_DIR}"/docker-compose.yml logs -f
    else
        ls -l "$TRACE_WEBAPP_LOGDIR"
    fi
}

exit 0
