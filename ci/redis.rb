# (C) Datadog, Inc. 2010-2016
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)

require './ci/common'

def redis_version
  ENV['FLAVOR_VERSION'] || '2.8.19'
end

def redis_rootdir
  "#{ENV['INTEGRATIONS_DIR']}/redis_#{redis_version}"
end

def redis_bin
  "#{redis_rootdir}/src/redis-server"
end

namespace :ci do
  namespace :redis do |flavor|
    task before_install: ['ci:common:before_install']

    task install: ['ci:common:install'] do
      # Downloads
      # https://github.com/antirez/redis/archive/#{redis_version}.zip
      unless File.exist? redis_bin
        sh %(curl -s -S -L\
             -o $VOLATILE_DIR/redis.zip\
             https://s3.amazonaws.com/dd-agent-tarball-mirror/redis-#{redis_version}.zip)
        sh %(rm -rf #{redis_rootdir} && mkdir -p #{redis_rootdir})
        sh %(mkdir -p $VOLATILE_DIR/redis)
        sh %(unzip -x $VOLATILE_DIR/redis.zip -d $VOLATILE_DIR/)
        sh %(mv -f $VOLATILE_DIR/redis-*/* #{redis_rootdir})
        sh %(cd #{redis_rootdir} && make -j $CONCURRENCY)
      end
    end

    task before_script: ['ci:common:before_script'] do
      # Run redis !
      sh %(#{redis_bin} $TRAVIS_BUILD_DIR/ci/resources/redis/auth.conf)
      sh %(#{redis_bin} $TRAVIS_BUILD_DIR/ci/resources/redis/noauth.conf)
      sh %(#{redis_bin} $TRAVIS_BUILD_DIR/ci/resources/redis/slave_healthy.conf)
      sh %(#{redis_bin} $TRAVIS_BUILD_DIR/ci/resources/redis/slave_unhealthy.conf)
    end

    task script: ['ci:common:script'] do
      this_provides = [
        'redis'
      ]
      Rake::Task['ci:common:run_tests'].invoke(this_provides)
    end

    task before_cache: ['ci:common:before_cache']

    task cleanup: ['ci:common:cleanup'] do
      # Shutdown redis
      conf_files = ["#{ENV['TRAVIS_BUILD_DIR']}/ci/resources/redis/auth.conf",
                    "#{ENV['TRAVIS_BUILD_DIR']}/ci/resources/redis/noauth.conf"]
      conf_files.each do |f|
        pass = nil
        port = nil
        File.readlines(f).each do |line|
          param = line.split(' ')
          if param[0] == 'port'
            port = param[1]
          elsif param[0] == 'requirepass'
            pass = param[1]
          end
        end
        if pass && port
          sh %(#{redis_rootdir}/src/redis-cli -p #{port} -a #{pass} SHUTDOWN)
        elsif port
          sh %(#{redis_rootdir}/src/redis-cli -p #{port} SHUTDOWN)
        end
      end
    end

    task :execute do
      Rake::Task['ci:common:execute'].invoke(flavor)
    end
  end
end
