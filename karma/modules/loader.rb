#!/usr/bin/env ruby
#
# Karma module loader/runner
#

require 'rexml/document'
require 'thwait'

#
# Basically what we do here is scan the modules path for desciptor XML
# files and create an in-memory module dependency graph out of that.
# For performance, this will later be serialized and cached.  When a
# module is requested to be run, all needed dependencies will be
# loaded at that time.  This will let you dynamically add/edit/reload
# exploits while keeping clients connected, etc.
#

module Karma

    #
    # Global configuration and constants
    #
    MODULES_DIR = File.expand_path(File.new(File::dirname(__FILE__)).path)
    MODULES = Hash.new()

    #
    # Scan a directory for module descriptors, create a new Module
    # instance for each one, and add the instance to the global
    # Modules table.
    # 
    def Karma.ScanModules(dir = MODULES_DIR)
        root = Dir.new(dir)
        root.each {|f|
            pathname = dir + "/" + f
            if (File.directory?(pathname) && f != "." && f != "..")
                ScanModules(pathname)
            elsif (f == "module.xml")
                m = Module.new(pathname)
                
                # Add to global modules table
                if (MODULES[m.id])
                    print "Warning: Replacing module id: @id"
                end
                MODULES[m.id] = m
            end
        }
    end
        

    #
    # The Module class implements the Composite/Proxy patterns where by
    # interacting with a module instance, certain operations may be
    # passed along to its depencies or dependents.
    #
    class Module

        attr_reader :path, :id, :version, :name, :file, :class, :handler,
                    :thread, :description, :options, :requires, :provides, 
                    :dependents

        private :load

        def initialize(descriptorFilePath)
            @loaded = false
            @running = false
            @dependents = []

            # Load descriptor XML file
            @path = File::dirname(descriptorFilePath)
            descriptor = File.new(descriptorFilePath)
            doc = REXML::Document.new(descriptor)
            root = doc.root

            # Parse out basic attributes (id, version, name, file)
            @id = root.attributes['id']
            @version = root.attributes['version']
            @name = root.attributes['name']
            @handler = root.attributes['handler']
            @description = root.elements['description']

            # File attribute is optional
            if (root.attributes['file'])
                @file = @path + "/" + root.attributes['file']
            end

            # Class attribute is optional
            @impl_class = nil
            if (root.attributes['class'])
                @class = root.attributes['class']
            end

            # Process module dependencies
            @requires = Hash.new()
            doc.elements.each('module/requires') { |element|
                id = element.attributes['id']
                @requires[id] = true
            }

            # Process module options
            @options = Hash.new()
            doc.elements.each('module/option') { |option|
                name = option.attributes['name']
                value = option.attributes['value']
                @options[name] = value
            }

            # Add provided symbols
            @provides = Hash.new()
            doc.elements.each('module/provides') { |element|
                id = element.attributes['id']
                @provides[id] = true
            }

        end

        def load()
            # Resolve dependency references before loading file
            @requires.each_key {|r| @requires[r] = MODULES[r] }

            # If we have a handler, it should have been specified as a
            # requirement, so it is safe to resolve that module
            # reference now as well
            if (@handler)
                @handler = MODULES[@handler]
            end

            #
            # TODO: Load modules in a thread w/ SAFE == 4.  This also
            # requires having a secure thread to handle requests for
            # things like 'require', etc.
            #
            if (@file)
                require(@file);
            end
            
            # Instantiate the module's main class with the default
            # options from the descriptor file
            if (@class)
                # spoonm's magic getClassForName trick
                @impl_class = Object.const_get(@class).new(self)
            end
            
            @loaded = true;
        end

        def run()
            # If we are already running, do nothing and return
            if @running
                return
            end

            # Load ourself if we are not already loaded
            if !@loaded
                load()
            end

            # Make sure each of our dependencies are running
            @requires.each_key {|r|
                # Locate module instance for dependency
                m = MODULES[r]
                
                if m != nil
                    m.run()
                    m.dependents.push(@id)
                else
                    raise "Non-existent dependency: " + r
                end
            }

            # If we have a handler, pass request to it
            # Otherwise, run the object that actually implements the module
            if (@handler)
                @handler.run_module(self)
            elsif (@impl_class)
                @thread = Thread.new() {
                    @impl_class.run()
                }
            end

            # Place module in MODULES table under each provided id
            @provides.each_key {|p|
#                 if (MODULES[p])
#                     puts "Warning: replacing provided symbol #{p}"
#                 end
                MODULES[p] = self
            }

            # Enter the running state
            puts " " + @id + " is running"
            @running = true
        end

	def run_module(m)
	    if (@impl_class)
		@impl_class.run_module(m)
	    end
	end

        def stop()
            if not @running
                return
            end

            @dependents.each() { |id|
                m = MODULES[id]
                m.stop()
            }

            if (@handler)
                @handler.stop_module(self)
            elsif (@impl_class)
                @impl_class.stop()
            end

            @requires.each_key {|r|
                # Locate module instance for dependency
                m = MODULES[r]
                
                if m != nil
                    m.dependents.push(@id)
                else
                    raise "Non-existent dependency: " + r
                end
            }

            puts " " + @id + " has stopped"
            @running = false
        end

	def stop_module(m)
	    if (@impl_class)
		@impl_class.stop_module(m)
	    end
	end
    end
end
