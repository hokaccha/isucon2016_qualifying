require 'logger'

worker_processes 20
preload_app true

timeout 120

pid "/tmp/unicorn.pid"
stderr_path "/tmp/unicorn-isuda-err.log"
stdout_path "/tmp/unicorn-isuda-out.log"
logger Logger.new($stderr).tap{|l| l.formatter = Logger::Formatter.new }

before_fork do |server, worker|
  old_pid_path = "/home/isucon/webapp/ruby/unicorn-isuda.pid.oldbin"
  if File.exists?(old_pid_path) && server.pid != old_pid_path
    begin
      Process.kill("QUIT", File.read(old_pid_path).to_i)
    rescue Errno::ENOENT, Errno::ESRCH
      # someone else did our job for us
    end
  end
end
