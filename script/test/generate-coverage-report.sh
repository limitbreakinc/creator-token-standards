forge coverage --ir-minimum --report lcov

lcov --remove ./lcov.info -o ./lcov.info.pruned '/test/mocks/*' 'test/mocks/*' '/test/adventures/*' 'test/adventures/*' '/test/utils/*' 'test/utils/*' '/script/common/*' 'script/common/*' 

genhtml lcov.info.pruned --output-directory coverage

open coverage/index.html