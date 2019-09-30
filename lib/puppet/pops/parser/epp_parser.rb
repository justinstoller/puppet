# The EppParser is a specialized Puppet Parser that starts parsing in Epp Text mode
class Puppet::Pops::Parser::EppParser < Puppet::Pops::Parser::Parser

  # Parses a file expected to contain epp text/DSL logic.
  def parse_file(file)
    unless FileTest.exist?(file)
      unless file =~ /\.epp$/
        file = file + ".epp"
      end
    end
    lexer = Puppet.lookup(:current_lexer)
    lexer.file = file
    _parse(lexer)
  end

  # Performs the parsing and returns the resulting model.
  # The lexer holds state, and this is setup with {#parse_string}, or {#parse_file}.
  #
  # TODO: deal with options containing origin (i.e. parsing a string from externally known location).
  # TODO: should return the model, not a Hostclass
  #
  # @api private
  #
  def _parse(lexer)
    begin
      @yydebug = false
      main = yyparse(lexer, :scan_epp)
      # #Commented out now because this hides problems in the racc grammar while developing
      # # TODO include this when test coverage is good enough.
      #      rescue Puppet::ParseError => except
      #        except.line ||= lexer.line
      #        except.file ||= lexer.file
      #        except.pos  ||= lexer.pos
      #        raise except
      #      rescue => except
      #        raise Puppet::ParseError.new(except.message, lexer.file, lexer.line, lexer.pos, except)
    end
    return main
  ensure
    lexer.clear
    @namestack = []
    @definitions = []
  end
end
