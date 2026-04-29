library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

package eth_pkg is
  subtype eth_byte_t is std_logic_vector(7 downto 0);
  type eth_frame_mem_t is array (natural range <>) of eth_byte_t;

  function crc32_next_byte(
    crc_in : std_logic_vector(31 downto 0);
    data   : std_logic_vector(7 downto 0)
  ) return std_logic_vector;
end package eth_pkg;

package body eth_pkg is
  function crc32_next_byte(
    crc_in : std_logic_vector(31 downto 0);
    data   : std_logic_vector(7 downto 0)
  ) return std_logic_vector is
    variable c   : std_logic_vector(31 downto 0) := crc_in;
    variable mix : std_logic;
  begin
    for i in 0 to 7 loop
      mix := c(0) xor data(i);
      c := '0' & c(31 downto 1);
      if mix = '1' then
        c := c xor x"EDB88320";
      end if;
    end loop;
    return c;
  end function;
end package body eth_pkg;
