library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.eth_pkg.all;

-- RMII MAC: preamble/SFD, frame bytes, FCS, IFG; RX captures frame including FCS.

entity eth_rmii_mac is
  generic (
    MAX_FRAME : natural := 128;
    IFG_CYC   : natural := 48
  );
  port (
    eth_refclk : in std_logic;

    eth_tx0   : out std_logic;
    eth_tx1   : out std_logic;
    eth_tx_en : out std_logic;
    eth_rx0   : in  std_logic;
    eth_rx1   : in  std_logic;
    eth_crs   : in  std_logic;

    rx_mem       : out eth_frame_mem_t(0 to MAX_FRAME - 1);
    rx_len       : out natural range 0 to MAX_FRAME;
    rx_done      : out std_logic;
    rx_overflow  : out std_logic;

    tx_mem       : in  eth_frame_mem_t(0 to MAX_FRAME - 1);
    tx_len       : in  natural range 0 to MAX_FRAME;
    tx_request   : in  std_logic;
    tx_busy      : out std_logic
  );
end entity;

architecture rtl of eth_rmii_mac is
  subtype byte_mem_t is eth_frame_mem_t(0 to MAX_FRAME - 1);

  signal rx_mem_i       : byte_mem_t := (others => (others => '0'));
  signal rx_byte        : eth_byte_t := (others => '0');
  signal rx_dibit_ix    : natural range 0 to 3 := 0;
  signal rx_len_i       : natural range 0 to MAX_FRAME := 0;
  signal rx_in_frame    : std_logic := '0';
  signal rx_seen_sfd    : std_logic := '0';
  signal rx_done_i      : std_logic := '0';
  signal rx_overflow_i  : std_logic := '0';

  signal tx_len_i       : natural range 0 to MAX_FRAME := 0;
  signal tx_busy_i      : std_logic := '0';

  type tx_state_t is (TX_IDLE, TX_PREAMBLE, TX_SFD, TX_DATA, TX_FCS, TX_IFG);
  signal tx_state    : tx_state_t := TX_IDLE;
  signal tx_index    : natural range 0 to MAX_FRAME := 0;
  signal tx_dibit_ix : natural range 0 to 3 := 0;
  signal tx_crc      : std_logic_vector(31 downto 0) := (others => '1');
  signal tx_fcs_data : std_logic_vector(31 downto 0) := (others => '0');
  signal tx_fcs_ix   : natural range 0 to 3 := 0;
  signal ifg_count   : natural range 0 to IFG_CYC := 0;

  signal txd  : std_logic_vector(1 downto 0) := "00";
  signal txen : std_logic := '0';

begin
  rx_mem      <= rx_mem_i;
  rx_len      <= rx_len_i;
  rx_done     <= rx_done_i;
  rx_overflow <= rx_overflow_i;
  tx_busy     <= tx_busy_i;

  eth_tx0   <= txd(0);
  eth_tx1   <= txd(1);
  eth_tx_en <= txen;

  process (eth_refclk)
    variable dibit       : std_logic_vector(1 downto 0);
    variable next_byte_v : eth_byte_t;
  begin
    if rising_edge(eth_refclk) then
      rx_done_i <= '0';
      dibit     := eth_rx1 & eth_rx0;

      if eth_crs = '1' then
        next_byte_v := rx_byte;
        case rx_dibit_ix is
          when 0 => next_byte_v(1 downto 0) := dibit;
          when 1 => next_byte_v(3 downto 2) := dibit;
          when 2 => next_byte_v(5 downto 4) := dibit;
          when 3 => next_byte_v(7 downto 6) := dibit;
        end case;
        rx_byte <= next_byte_v;

        if rx_dibit_ix = 3 then
          rx_dibit_ix <= 0;
          if rx_seen_sfd = '0' then
            if next_byte_v = x"D5" then
              rx_seen_sfd   <= '1';
              rx_len_i      <= 0;
              rx_overflow_i <= '0';
            end if;
          else
            if rx_len_i < MAX_FRAME then
              rx_mem_i(rx_len_i) <= next_byte_v;
              rx_len_i             <= rx_len_i + 1;
            else
              rx_overflow_i <= '1';
            end if;
          end if;
        else
          rx_dibit_ix <= rx_dibit_ix + 1;
        end if;

        rx_in_frame <= '1';
      else
        if rx_in_frame = '1' and rx_seen_sfd = '1' and rx_overflow_i = '0' then
          rx_done_i <= '1';
        end if;
        rx_in_frame   <= '0';
        rx_seen_sfd   <= '0';
        rx_dibit_ix   <= 0;
        rx_byte       <= (others => '0');
      end if;
    end if;
  end process;

  tx_len_i <= tx_len;

  process (eth_refclk)
    variable current_byte : eth_byte_t;
    variable next_crc     : std_logic_vector(31 downto 0);
    variable final_crc    : std_logic_vector(31 downto 0);
  begin
    if rising_edge(eth_refclk) then
      case tx_state is
        when TX_IDLE =>
          txd       <= "00";
          txen      <= '0';
          tx_busy_i <= '0';
          if tx_request = '1' then
            tx_busy_i   <= '1';
            tx_state    <= TX_PREAMBLE;
            tx_dibit_ix <= 0;
            tx_index    <= 0;
            tx_crc      <= (others => '1');
          end if;

        when TX_PREAMBLE =>
          txen <= '1';
          current_byte := x"55";
          txd  <= current_byte(tx_dibit_ix * 2 + 1 downto tx_dibit_ix * 2);
          if tx_dibit_ix = 3 then
            tx_dibit_ix <= 0;
            if tx_index = 6 then
              tx_index <= 0;
              tx_state <= TX_SFD;
            else
              tx_index <= tx_index + 1;
            end if;
          else
            tx_dibit_ix <= tx_dibit_ix + 1;
          end if;

        when TX_SFD =>
          txen <= '1';
          current_byte := x"D5";
          txd  <= current_byte(tx_dibit_ix * 2 + 1 downto tx_dibit_ix * 2);
          if tx_dibit_ix = 3 then
            tx_dibit_ix <= 0;
            tx_index    <= 0;
            tx_state    <= TX_DATA;
          else
            tx_dibit_ix <= tx_dibit_ix + 1;
          end if;

        when TX_DATA =>
          txen         <= '1';
          current_byte := tx_mem(tx_index);
          txd          <= current_byte(tx_dibit_ix * 2 + 1 downto tx_dibit_ix * 2);

          if tx_dibit_ix = 3 then
            next_crc    := crc32_next_byte(tx_crc, current_byte);
            tx_crc      <= next_crc;
            tx_dibit_ix <= 0;
            if tx_index = tx_len_i - 1 then
              final_crc  := not next_crc;
              tx_fcs_data <= final_crc;
              tx_fcs_ix  <= 0;
              tx_state   <= TX_FCS;
            else
              tx_index <= tx_index + 1;
            end if;
          else
            tx_dibit_ix <= tx_dibit_ix + 1;
          end if;

        when TX_FCS =>
          txen <= '1';
          case tx_fcs_ix is
            when 0 => current_byte := tx_fcs_data(7 downto 0);
            when 1 => current_byte := tx_fcs_data(15 downto 8);
            when 2 => current_byte := tx_fcs_data(23 downto 16);
            when others => current_byte := tx_fcs_data(31 downto 24);
          end case;
          txd <= current_byte(tx_dibit_ix * 2 + 1 downto tx_dibit_ix * 2);

          if tx_dibit_ix = 3 then
            tx_dibit_ix <= 0;
            if tx_fcs_ix = 3 then
              tx_state  <= TX_IFG;
              ifg_count <= 0;
              txen      <= '0';
              txd       <= "00";
            else
              tx_fcs_ix <= tx_fcs_ix + 1;
            end if;
          else
            tx_dibit_ix <= tx_dibit_ix + 1;
          end if;

        when TX_IFG =>
          txen <= '0';
          txd  <= "00";
          if ifg_count = IFG_CYC then
            tx_state <= TX_IDLE;
          else
            ifg_count <= ifg_count + 1;
          end if;
      end case;
    end if;
  end process;
end architecture;
