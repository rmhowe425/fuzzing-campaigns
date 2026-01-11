# ASAN Environment Variables
export ASAN_OPTIONS=detect_leaks=0:fast_unwind_on_malloc=1:check_initialization_order=1:malloc_context_size=3:symbolize=0:abort_on_error=1
export ASAN_SYMBOLIZER_PATH=/usr/local/bin/llvm-symbolizer
export AFL_USE_ASAN=1
export AFL_NO_AFFINITY=1
export AFL_PERSISTENT=1


# UBSAN Environment Variables
export AFL_USE_UBSAN=1
export AFL_NO_AFFINITY=1
export UBSAN_OPTIONS=print_stacktrace=1:report_error_type=1
export AFL_PERSISTENT=1


# MSAN Environment Variables
export AFL_USE_MSAN=1
export AFL_NO_AFFINITY=1
export MSAN_OPTIONS=verbosity=1:poison_heap=1:poison_stack=1:poison_global=1
export AFL_PERSISTENT=1


# Custom Mutators
AFL_CUSTOM_MUTATOR_LIBRARY=/home/development/exploit-dev/fuzz_libxls/mutators/main_mutator.so
AFL_CUSTOM_MUTATOR_LIBRARY=/home/development/exploit-dev/fuzz_libxls/mutators/formula_focused_mutator.so
AFL_CUSTOM_MUTATOR_LIBRARY=/home/development/exploit-dev/fuzz_libxls/mutators/biff_record_mutator.so

# AFL-Fuzz Commands
	# main harness
	nice -n 10 ionice -c3 taskset -c 0 afl-fuzz -i seeds/main_harness -o out -M asan_main_master -p explore -x dictionaries/main_harness.dict -- ./build_asan/libxls-1.6.3/main_harness @@
        nice -n 10 ionice -c3 taskset -c 1 afl-fuzz -i seeds/main_harness -o out -S asan_main_secondary -x dictionaries/main_harness.dict -- ./build_asan/libxls-1.6.3/main_harness @@
        nice -n 10 ionice -c3 taskset -c 2 afl-fuzz -i seeds/main_harness -o out -S ubsan_main_secondary -p exploit -x dictionaries/main_harness.dict -- ./build_ubsan/libxls-1.6.3/main_harness @@
        nice -n 10 ionice -c3 taskset -c 3 afl-fuzz -i seeds/main_harness -o out -S msan_main_secondary -p exploit -x dictionaries/main_harness.dict -- ./build_msan/libxls-1.6.3/main_harness @@

        # biff harness
        nice -n 10 ionice -c3 taskset -c 4 afl-fuzz -i seeds/biff_harness -o out -S asan_biff_secondary1 -x dictionaries/biff_harness.dict
        nice -n 10 ionice -c3 taskset -c 5 afl-fuzz -i seeds/biff_harness -o out -S asan_biff_secondary2 -p exploit -x dictionaries/biff_harness.dict
        nice -n 10 ionice -c3 taskset -c 6 afl-fuzz -i seeds/biff_harness -o out -S ubsan_biff_secondary -p exploit -x dictionaries/biff_harness.dict
        nice -n 10 ionice -c3 taskset -c 7 afl-fuzz -i seeds/biff_harness -o out -S msan_biff_secondary -p exploit -x dictionaries/biff_harness.dict
        nice -n 10 ionice -c3 taskset -c 8 afl-fuzz -i seeds/biff_harness -o out -S cmplog_biff_secondary -x dictionaries/biff_harness.dict
        
        # formula harness
        nice -n 10 ionice -c3 taskset -c 9 afl-fuzz -i seeds/formula_harness -o out -S asan_formula_secondary1 -x dictionaries/formula_harness.dict
        nice -n 10 ionice -c3 taskset -c 10 afl-fuzz -i seeds/formula_harness -o out -S asan_formula_secondary2 -p exlore -x dictionaries/formula_harness.dict
        nice -n 10 ionice -c3 taskset -c 11 afl-fuzz -i seeds/formula_harness -o out -S ubsan_formula_secondary -p exploit -x dictionaries/formula_harness.dict
        nice -n 10 ionice -c3 taskset -c 12 afl-fuzz -i seeds/formula_harness -o out -S msan_formula_secondary -p exploit -x dictionaries/formula_harness.dict
