library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.eth_pkg.all;

-- RMII / LAN8720: ARP + ICMP echo reply. MAC 02:12:34:56:78:9A, IP 192.168.1.10.

entity lan8720_top is
  port (
    eth_tx0    : out   std_logic;
    eth_tx1    : out   std_logic;
    eth_tx_en  : out   std_logic;
    eth_rx0    : in    std_logic;
    eth_rx1    : in    std_logic;
    eth_crs    : in    std_logic;

    eth_refclk : in    std_logic;
    eth_mdc    : out   std_logic;
    eth_mdio   : inout std_logic;

    debug_out  : out   std_logic;
    uart_tx    : out   std_logic
  );
end entity;

architecture rtl of lan8720_top is
  constant MAX_FRAME : natural := 128;
  constant IFG_CYC   : natural := 48;

  subtype byte_mem_t is eth_frame_mem_t(0 to MAX_FRAME - 1);

  constant FPGA_MAC0 : eth_byte_t := x"02";
  constant FPGA_MAC1 : eth_byte_t := x"12";
  constant FPGA_MAC2 : eth_byte_t := x"34";
  constant FPGA_MAC3 : eth_byte_t := x"56";
  constant FPGA_MAC4 : eth_byte_t := x"78";
  constant FPGA_MAC5 : eth_byte_t := x"9A";

  constant FPGA_IP0 : eth_byte_t := x"C0";
  constant FPGA_IP1 : eth_byte_t := x"A8";
  constant FPGA_IP2 : eth_byte_t := x"01";
  constant FPGA_IP3 : eth_byte_t := x"0A";

  signal rx_mem : byte_mem_t := (others => (others => '0'));
  signal tx_mem : byte_mem_t := (others => (others => '0'));

  signal rx_len      : natural range 0 to MAX_FRAME := 0;
  signal rx_done     : std_logic := '0';
  signal rx_overflow : std_logic := '0';

  signal tx_len     : natural range 0 to MAX_FRAME := 0;
  signal tx_request : std_logic := '0';
  signal tx_busy    : std_logic := '0';

  signal reply_count : unsigned(7 downto 0) := (others => '0');

  function fold_sum(sum_in : unsigned(19 downto 0)) return unsigned is
    variable s : unsigned(19 downto 0) := sum_in;
  begin
    for i in 0 to 3 loop
      s := resize(s(15 downto 0), 20) + resize(s(19 downto 16), 20);
    end loop;
    return s;
  end function;

  function word_from_bytes(hi : eth_byte_t; lo : eth_byte_t) return unsigned is
  begin
    return unsigned(std_logic_vector'(hi & lo));
  end function;

begin
  eth_mdc  <= '0';
  eth_mdio <= 'Z';
  uart_tx  <= '1';

  debug_out <= reply_count(0);

  mac_inst : entity work.eth_rmii_mac
    generic map (
      MAX_FRAME => MAX_FRAME,
      IFG_CYC   => IFG_CYC
    )
    port map (
      eth_refclk  => eth_refclk,
      eth_tx0     => eth_tx0,
      eth_tx1     => eth_tx1,
      eth_tx_en   => eth_tx_en,
      eth_rx0     => eth_rx0,
      eth_rx1     => eth_rx1,
      eth_crs     => eth_crs,
      rx_mem      => rx_mem,
      rx_len      => rx_len,
      rx_done     => rx_done,
      rx_overflow => rx_overflow,
      tx_mem      => tx_mem,
      tx_len      => tx_len,
      tx_request  => tx_request,
      tx_busy     => tx_busy
    );

  process (eth_refclk)
    variable is_for_us      : boolean;
    variable is_broadcast   : boolean;
    variable is_arp         : boolean;
    variable is_ipv4        : boolean;
    variable is_icmp_echo   : boolean;
    variable ihl_bytes      : natural range 0 to 60;
    variable ip_total_len   : natural range 0 to MAX_FRAME;
    variable icmp_start     : natural range 0 to MAX_FRAME;
    variable icmp_len       : natural range 0 to MAX_FRAME;
    variable frame_len      : natural range 0 to MAX_FRAME;
    variable sum            : unsigned(19 downto 0);
    variable folded         : unsigned(19 downto 0);
    variable csum           : std_logic_vector(15 downto 0);
    variable word16         : unsigned(15 downto 0);
  begin
    if rising_edge(eth_refclk) then
      tx_request <= '0';

      if rx_done = '1' and tx_busy = '0' and tx_request = '0' then
        is_for_us :=
          rx_mem(0) = FPGA_MAC0 and rx_mem(1) = FPGA_MAC1 and
          rx_mem(2) = FPGA_MAC2 and rx_mem(3) = FPGA_MAC3 and
          rx_mem(4) = FPGA_MAC4 and rx_mem(5) = FPGA_MAC5;

        is_broadcast :=
          rx_mem(0) = x"FF" and rx_mem(1) = x"FF" and rx_mem(2) = x"FF" and
          rx_mem(3) = x"FF" and rx_mem(4) = x"FF" and rx_mem(5) = x"FF";

        is_arp  := rx_len >= 46 and rx_mem(12) = x"08" and rx_mem(13) = x"06";
        is_ipv4 := rx_len >= 38 and rx_mem(12) = x"08" and rx_mem(13) = x"00";

        if is_arp and is_broadcast then
          if rx_mem(14) = x"00" and rx_mem(15) = x"01" and
             rx_mem(16) = x"08" and rx_mem(17) = x"00" and
             rx_mem(18) = x"06" and rx_mem(19) = x"04" and
             rx_mem(20) = x"00" and rx_mem(21) = x"01" and
             rx_mem(38) = FPGA_IP0 and rx_mem(39) = FPGA_IP1 and
             rx_mem(40) = FPGA_IP2 and rx_mem(41) = FPGA_IP3 then

            for i in 0 to 5 loop
              tx_mem(i) <= rx_mem(6 + i);
            end loop;
            tx_mem(6)  <= FPGA_MAC0;
            tx_mem(7)  <= FPGA_MAC1;
            tx_mem(8)  <= FPGA_MAC2;
            tx_mem(9)  <= FPGA_MAC3;
            tx_mem(10) <= FPGA_MAC4;
            tx_mem(11) <= FPGA_MAC5;
            tx_mem(12) <= x"08";
            tx_mem(13) <= x"06";

            tx_mem(14) <= x"00"; tx_mem(15) <= x"01";
            tx_mem(16) <= x"08"; tx_mem(17) <= x"00";
            tx_mem(18) <= x"06"; tx_mem(19) <= x"04";
            tx_mem(20) <= x"00"; tx_mem(21) <= x"02";
            tx_mem(22) <= FPGA_MAC0;
            tx_mem(23) <= FPGA_MAC1;
            tx_mem(24) <= FPGA_MAC2;
            tx_mem(25) <= FPGA_MAC3;
            tx_mem(26) <= FPGA_MAC4;
            tx_mem(27) <= FPGA_MAC5;
            tx_mem(28) <= FPGA_IP0;
            tx_mem(29) <= FPGA_IP1;
            tx_mem(30) <= FPGA_IP2;
            tx_mem(31) <= FPGA_IP3;
            for i in 0 to 5 loop
              tx_mem(32 + i) <= rx_mem(22 + i);
            end loop;
            tx_mem(38) <= rx_mem(28);
            tx_mem(39) <= rx_mem(29);
            tx_mem(40) <= rx_mem(30);
            tx_mem(41) <= rx_mem(31);

            tx_len     <= 42;
            tx_request <= '1';
            reply_count <= reply_count + 1;
          end if;

        elsif is_ipv4 and is_for_us then
          ihl_bytes := to_integer(unsigned(rx_mem(14)(3 downto 0))) * 4;
          ip_total_len := to_integer(word_from_bytes(rx_mem(16), rx_mem(17)));
          icmp_start := 14 + ihl_bytes;

          is_icmp_echo := false;
          if ihl_bytes = 20 and ip_total_len >= ihl_bytes + 8 then
            if rx_len >= 14 + ip_total_len + 4 and
               rx_mem(23) = x"01" and
               rx_mem(30) = FPGA_IP0 and rx_mem(31) = FPGA_IP1 and
               rx_mem(32) = FPGA_IP2 and rx_mem(33) = FPGA_IP3 and
               rx_mem(icmp_start) = x"08" then
              is_icmp_echo := true;
            end if;
          end if;

          if is_icmp_echo then
            frame_len := 14 + ip_total_len;
            icmp_len  := ip_total_len - ihl_bytes;

            for i in 0 to MAX_FRAME - 1 loop
              if i < frame_len then
                tx_mem(i) <= rx_mem(i);
              end if;
            end loop;

            for i in 0 to 5 loop
              tx_mem(i) <= rx_mem(6 + i);
            end loop;
            tx_mem(6)  <= FPGA_MAC0;
            tx_mem(7)  <= FPGA_MAC1;
            tx_mem(8)  <= FPGA_MAC2;
            tx_mem(9)  <= FPGA_MAC3;
            tx_mem(10) <= FPGA_MAC4;
            tx_mem(11) <= FPGA_MAC5;

            tx_mem(26) <= rx_mem(30);
            tx_mem(27) <= rx_mem(31);
            tx_mem(28) <= rx_mem(32);
            tx_mem(29) <= rx_mem(33);
            tx_mem(30) <= rx_mem(26);
            tx_mem(31) <= rx_mem(27);
            tx_mem(32) <= rx_mem(28);
            tx_mem(33) <= rx_mem(29);

            tx_mem(icmp_start)     <= x"00";
            tx_mem(icmp_start + 2) <= x"00";
            tx_mem(icmp_start + 3) <= x"00";
            tx_mem(24) <= x"00";
            tx_mem(25) <= x"00";

            sum := (others => '0');
            -- IHL fixed at 20 bytes here => 10 header words (indices 0..9).
            for wi in 0 to 9 loop
              if wi = 5 then
                word16 := (others => '0');
              elsif wi = 6 then
                word16 := word_from_bytes(rx_mem(30), rx_mem(31));
              elsif wi = 7 then
                word16 := word_from_bytes(rx_mem(32), rx_mem(33));
              elsif wi = 8 then
                word16 := word_from_bytes(rx_mem(26), rx_mem(27));
              elsif wi = 9 then
                word16 := word_from_bytes(rx_mem(28), rx_mem(29));
              else
                word16 := word_from_bytes(rx_mem(14 + wi * 2), rx_mem(15 + wi * 2));
              end if;
              sum := fold_sum(sum + resize(word16, 20));
            end loop;
            folded := fold_sum(sum);
            csum := not std_logic_vector(folded(15 downto 0));
            tx_mem(24) <= csum(15 downto 8);
            tx_mem(25) <= csum(7 downto 0);

            sum := (others => '0');
            for i in 0 to MAX_FRAME / 2 - 1 loop
              if i * 2 < icmp_len then
                if i = 1 then
                  word16 := (others => '0');
                elsif i * 2 + 1 < icmp_len then
                  if i = 0 then
                    word16 := word_from_bytes(x"00", rx_mem(icmp_start + 1));
                  else
                    word16 := word_from_bytes(rx_mem(icmp_start + i * 2), rx_mem(icmp_start + i * 2 + 1));
                  end if;
                else
                  word16 := word_from_bytes(rx_mem(icmp_start + i * 2), x"00");
                end if;
                sum := fold_sum(sum + resize(word16, 20));
              end if;
            end loop;
            folded := fold_sum(sum);
            csum := not std_logic_vector(folded(15 downto 0));
            tx_mem(icmp_start + 2) <= csum(15 downto 8);
            tx_mem(icmp_start + 3) <= csum(7 downto 0);

            tx_len     <= frame_len;
            tx_request <= '1';
            reply_count <= reply_count + 1;
          end if;
        end if;
      end if;
    end if;
  end process;
end architecture;
