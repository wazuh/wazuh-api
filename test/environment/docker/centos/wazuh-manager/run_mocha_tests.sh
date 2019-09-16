#!/bin/sh

TEST_PATH=./test
TIMEOUT=10000
REPORTER=./node_modules/mochawesome
REPORT_DIR=/share
ARGS="--timeout=${TIMEOUT} --reporter ${REPORTER} --reporter-options reportDir=${REPORT_DIR},reportFilename="

REPORT_NAME=active_response
mocha ${TEST_PATH}/test_active_response.js ${ARGS}${REPORT_NAME}

REPORT_NAME=agents
mocha ${TEST_PATH}/test_agents.js ${ARGS}${REPORT_NAME}
sleep 10

REPORT_NAME=agents2
mocha ${TEST_PATH}/test_agents_2.js ${ARGS}${REPORT_NAME}

REPORT_NAME=app
mocha ${TEST_PATH}/test_app.js ${ARGS}${REPORT_NAME}

REPORT_NAME=cluster
mocha ${TEST_PATH}/test_cluster.js ${ARGS}${REPORT_NAME}
sleep 10

REPORT_NAME=decoders
mocha ${TEST_PATH}/test_decoders.js ${ARGS}${REPORT_NAME}

REPORT_NAME=lists
mocha ${TEST_PATH}/test_lists.js ${ARGS}${REPORT_NAME}

REPORT_NAME=manager
mocha ${TEST_PATH}/test_manager.js ${ARGS}${REPORT_NAME}
sleep 10

REPORT_NAME=rootcheck
mocha ${TEST_PATH}/test_rootcheck.js ${ARGS}${REPORT_NAME}

REPORT_NAME=rules
mocha ${TEST_PATH}/test_rules.js ${ARGS}${REPORT_NAME}

REPORT_NAME=sca
mocha ${TEST_PATH}/test_sca.js ${ARGS}${REPORT_NAME}

REPORT_NAME=test_syscheck
ARGS=$ARGS
mocha ${TEST_PATH}/test_syscheck.js ${ARGS}${REPORT_NAME}

REPORT_NAME=syscollector
mocha ${TEST_PATH}/test_syscollector.js ${ARGS}${REPORT_NAME}

chmod +r ${TEST_PATH}/*
