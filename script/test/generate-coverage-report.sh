forge coverage --report lcov

lcov --remove ./lcov.info -o ./lcov.info.pruned '/test/mocks/*' 'test/mocks/*' '/test/v2/mocks/*' 'test/v2/mocks/*' '/test/adventures/*' 'test/adventures/*' '/test/v2/adventures/*' 'test/v2/adventures/*'

genhtml lcov.info.pruned --output-directory coverage

open coverage/index.html