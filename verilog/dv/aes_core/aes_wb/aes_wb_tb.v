// Copyright 2020 Antmicro
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

`default_nettype none


`timescale 10 ns / 10 ps

`include "../../../../verilog/rtl/defines.v"
`include "../../../../verilog/rtl/mprj_ctrl.v"
`include "../../../../verilog/rtl/src/aes_core.v"
`include "../../../../verilog/rtl/src/aes_128/aes_cipher_top.v"
`include "../../../../verilog/rtl/src/aes_128/aes_inv_cipher_top.v"
`include "../../../../verilog/rtl/src/aes_128/aes_sbox.v"
`include "../../../../verilog/rtl/src/aes_128/aes_inv_sbox.v"
`include "../../../../verilog/rtl/src/aes_128/aes_rcon.v"
`include "../../../../verilog/rtl/src/aes_128/aes_key_expand_128.v"

module aes_wb_tb;

    // Params
    localparam TEST_DATA = 32'hFFFFFFFF;
    localparam CTRL_ADDR = 32'h00000000;

    localparam ENC_KEY_1 = 32'h00000004;
    localparam ENC_KEY_2 = 32'h00000008;
    localparam ENC_KEY_3 = 32'h0000000C;
    localparam ENC_KEY_4 = 32'h00000010;

    localparam ENC_TXT_1 = 32'h00000014;
    localparam ENC_TXT_2 = 32'h00000018;
    localparam ENC_TXT_3 = 32'h0000001C;
    localparam ENC_TXT_4 = 32'h00000020;

    // Wishbone ports
    reg wb_clk_i;
    reg wb_rst_i;

    reg wb_stb_i;
    reg wb_cyc_i;
    reg wb_we_i;
    reg [3:0] wb_sel_i;
    reg [31:0] wb_dat_i;
    reg [31:0] wb_adr_i;

    wire wb_ack_o;
    wire [31:0] wb_dat_o;

    initial begin
        wb_clk_i = 0;
        wb_rst_i = 0;
        wb_stb_i = 0;
        wb_cyc_i = 0;
        wb_sel_i = 0;
        wb_we_i  = 0;
        wb_dat_i = 0;
        wb_adr_i = 0;
    end

    always #1 wb_clk_i = ~wb_clk_i;

    // Mega Project Control Registers
    wire [31:0] mprj_ctrl = 32'h30000000;

    initial begin
        $dumpfile("aes_wb_tb.vcd");
        $dumpvars(0, aes_wb_tb);
        repeat (50) begin
            repeat (1000) @(posedge wb_clk_i);
        end
        $display("%c[1;31m",27);
        $display ("Monitor: Timeout, Test Mega-Project Control aes_wb Failed");
        $display("%c[0m",27);
        $finish;
    end

    // Variables for testing
    reg[31:0] test_data;
    reg[127:0] ciph;
    integer addr;
    integer tv_it;

    // Testvectors for aes Encryption/Decryption
    reg[383:0] tv[63:0];

    initial begin
        tv[0]= 384'h4f2f8b71e8c5340f0b21fd95af7fe629436f620f120bce3cd275a91df918d31daaaa92503215c96bb93e66d7a6c32e90;
        tv[1]= 384'ha51e73925c9b57d14d48e2426690982501203d5b5b589cbc46115c899d069dab3e9bcfb49af4cea5d589dee62e79fedd;
        tv[2]= 384'h745e5e18146a10f48f35bc4fd5a840d9677303c7a6b66dad4fd362219b82529b94473eedb74021052119bb069e18af6f;
        tv[3]= 384'h76f6bc2f75647d18435b75f8f432ff6397408576082bd73aac7951a49a51e559b826563cf370b60e5508be188c9df986;
        tv[4]= 384'ha5b891fd970cf888eaba554be4be18f44758d2a56c58f5fc83456fae4f64dc112ee872d495a15e2b006e7d9de57661e0;
        tv[5]= 384'h49364a22f609886537d5693bab74c0dcb2d74e707ab25c91b1834e91d97f5d77ee591776604848ab2cacc9401f2ea0dc;
        tv[6]= 384'ha70fe1d9b9786f4f9ac1e8ddfbdc4b3e690910baed903476b20fc5492e9d947cfe9e734abd4df26bdaf46f3e2dae9cd7;
        tv[7]= 384'hbfddf0ebcf0ff89e3ae1a6de0417fd072a00743b6772f314789423a4c153e8c457572536881ff7a30e9a3fec6ad20a96;
        tv[8]= 384'hf7a8300a944fe0e61dc874740298d954ab698cd496fd0c0b5172623f7502ffecd1efffaf5792af963f71b82837606987;
        tv[9]= 384'h2e4d0e79bad17b772ebe12a62aba23940b246609c8d896e9d317790e81b5b92ef276c0d05e959c770940656e5cac8c32;
        tv[10]= 384'h3e086e1d6e21344764e7d87d5948093bf6f810d2badb90cb9a7790e5ca47ecf2f66502ac286b5088103195818568e5e5;
        tv[11]= 384'h3707a873695c3f98fbd8afaf4242914e0e2c5aebe5687ff180e34f76c20019e1b9c9835b89338b2a3267e9ae47ef71eb;
        tv[12]= 384'heea7247fd1f806d6bdb4aa6feceeb6fa1c7eff69e37327a34519165f652caf4245c93ca88fab33816d8402089309dd37;
        tv[13]= 384'h2c319c8ed10d254eba53cb16a4dc15173375cb3ef8ed2a866b9c32550f870f44629d5f8aeb56e06d91b51faacf449bca;
        tv[14]= 384'hb4e50786a638f71e7ad91860ae76ba646610071b0aee0f3a30ce28aaae1063e79469c025c7d98b80f29258589110f02a;
        tv[15]= 384'hbefff49e29b13ea0b025ad0054579e5e7d1ef780eddeabbd2c0b5434d0feca41922e00b4142d4bdcc7c22da0f133daa8;
        tv[16]= 384'h42b80e1ca41d12b4768dafc6e53aa9e3659617166f694d81fb4e02c168326e4bf4ecafecc5380bc42f5603bcfbfdea7c;
        tv[17]= 384'h979bc3932e901321e2d8afdbb4933d2a656de003aaca66780cafa55d64b39ccaaba07bc36e919335cc6a718516541d69;
        tv[18]= 384'hf3d90b271c12e4ed600615daed1f1596dc3064f4058f767c7c05a204188d08d13a283048671f8a249372fae2b766b6ad;
        tv[19]= 384'hd175d5d06b8ac8c8b4c651abf2155b04cdeeffe003bcceb4a7cd765cec7e9fe9240c68dbbae426be43e5e692115c8274;
        tv[20]= 384'hfaed3e76d36b0f9187bcb541f98ebeff75932718c874ab85b2bc1aab4aa5d5f44e6cd653c7eecc7a254158a431a561fb;
        tv[21]= 384'h1e70d1c74ea858439af93507d27848f63c7c682df28bd490a8c381d2f39457f3bb4280a9d527cc86990136283ed21cd2;
        tv[22]= 384'hc6f98d0b79ce6f2a275905476a9eac4b93fb8a1e7134ca2e57058adbc6078227b68cf2ee6abcc25a5c46b4ecadde2e39;
        tv[23]= 384'hcf882ef38bc7b7656235de0f1f87d4b31e278d5881a3d116be4c779cbf38eb652b48d5e579ddfe795b9894123f97a1e7;
        tv[24]= 384'h95c532540e1915138351b35cb121f4b684df5f29969fd37d890c33519d0593d8b76ea8e8f205bc0c531f413fe2baf2c2;
        tv[25]= 384'h6aede9f1de0f6e38aaf7eef72e7c18559fee11dcf5225724923e666bdfa66211a5bd05912ed0a57be57e7bec660f7e14;
        tv[26]= 384'h135fbeb746440290e1e879ca1999062e48fc4a011501a64b490d372c92c1c73fe6a91b007e4264da067d7bae90132d1a;
        tv[27]= 384'haeedd4cefde3aef86bac1444ab9548606ad28486ce0f7396fd477e1db929ce4c4e61e50f6c9fd65915c276dd1e8425bc;
        tv[28]= 384'hfc0eb6b5e9e9f3f088c459bf0578b9e841027acbfd3d7dc50806baa226669942aa7995ac11667ef2f865c424a1cd52ed;
        tv[29]= 384'h3dd2d31bbc2eeb05b191eb7715165c295d12c50a3d0767b433cf07842a2dbcf6af9214f4984e9cbf2a0cf7674532c873;
        tv[30]= 384'h242c307936575b5db3911325576da75e36d8c5e1581bfc211c77f8fcc0b95e953352d421a50378ce0a65dc860cd1ed33;
        tv[31]= 384'h6205985bd81be5bbb028fa4bf7e9fc521ecd27087c2b95bdaf64ed30577983c7ad3c34f066508a4d70fcdcec3fa174cd;
        tv[32]= 384'h0931fe96fd5cfa706b6758fbb20174164d2caf7a8720f0ef6e21aa7965029972082c20fbc07caa3706d4710ae9380a8c;
        tv[33]= 384'hb26d1bd0ca03f0be63db9691a5d0ef16baf10d1abce9c99b7e9b2ac989d861d1205870ae28032bf2890a70b1311ca163;
        tv[34]= 384'he0f2178a0664309104122a995dd93fbff30268af76d3834ca15f574cdafa343c69bfb7172c79efba674dc368b063ee34;
        tv[35]= 384'ha1afb603d1f73575ba0ea8f9fda4e9bfdca687b914bbc24f85b853909c23bcb1465c422f831c7129c3298018bffc20c4;
        tv[36]= 384'h091e74c5fe8a43cdc8ec16222f83d720c06b4bcddf86c6b83feb0a4b2ffa805d575e2ed8c5e980a89f444acf24fd8012;
        tv[37]= 384'h0a5f0c977a399e66abc3cf061392ed53e916ff2a4871544b58912f7300994fd333c0c351e615743f6e65fd48c03e85db;
        tv[38]= 384'ha45e4a0ce0104f99ac1253fbc3ec413d9baeda6dd9f62db96401524d57d53adbbac8dcbf789e274310a8231a1993b5ce;
        tv[39]= 384'h6c06944fae1e9e63b560358b94090c6df17437557917f477b64a550b9bb6dcd3a4d23696076eb887add302901d1f9871;
        tv[40]= 384'hf77a51a2a292952751e8de968114823481e768228d10faf21c148915d1c590551d72c403525cb1f682e5d3efd2fa10a7;
        tv[41]= 384'hd77d257f82697ffe8cfb05e6d641fdf9e1fe9b8f39010bfa8e1ab44b673fe3ed6880b9e2db81d0c5062e7b1aa3c957e0;
        tv[42]= 384'h0e2ddb3145d721f51aee00c457d8f8d736584ca388f4d5b1df0b5fe2054d9e0068ad5198e4b77077011a4d565ccd256b;
        tv[43]= 384'ha4a999b687155ed39a5146763284714c8044ef41dc0527512a86e44257c9b478a751ff1c16545e1326c7618d29f45873;
        tv[44]= 384'h434cf99ffbe185676c2b52f0dc5c68a5eb7d0a0fa1e6b7178e801a2a301c3ec18cd8cd07f636cb343f4d504c0ec76bad;
        tv[45]= 384'h82d985d1ec53c51094c224cb43936f36de78c7c630b57323b49335af70f91045e5e88caf38785f8589eee8337afb4608;
        tv[46]= 384'h82e1f25ed6d0fbc23bed535f058f5cba9af107cb80adb56be1f169ced2e86ca60bc9425a6dd2db3ef651afb2689122b8;
        tv[47]= 384'hd4e64cafdda8f1f7929328d399d5b39e7413a3d0d501eaf358eb0ab0f61b47d31ffbfa237a2d54f994a13be04de393ff;
        tv[48]= 384'h5aa1a1e2887f142cc0f8c0a39a19a457ffc6257d136973f3fd115947fadde4c8916dba9b635c97543ab9d3b8af71a556;
        tv[49]= 384'h72553a927184089d223f3e8dd27ff0c8b16198a616081e3c96b3e5eba40c4965df4491fa51b66fbbba3ee77873ebe353;
        tv[50]= 384'h7b1ab0bbc443715625810ca202c7aad3b3948886fb2fd53bae162a9252983c2ff96674247c1f6605970975c7894b0a53;
        tv[51]= 384'h2389b0fe817d3b5027a2c6b21909ac209bb96803b6b10c8bb13ff20db3162f5fd43fe8b97d8b65f92e701287b519e601;
        tv[52]= 384'h3e79308a00fb45bffa2f264f4997d865dbbebfc7e8a4a6f4004310fbe2c0a46b9396768000d4da56a3c500f8e7e94b8b;
        tv[53]= 384'h5a8d0efaa0e21e6f894ed6c873c37920767b22cd600bec91e1ff52c68823f0b791a5f2747b50f1e7f54bb88a01492f4b;
        tv[54]= 384'h8c9c83a4e33b09e4ce68679002ca3ac0cbc90b93c4e8540ee83a7d7c43ba2e3515b165f53a7e2a04500e7002dcc015ed;
        tv[55]= 384'h8f3244495167c11a64d774ec90a3482ee0a5c46a35ae01b8246960cd637540510179c37fdcd10a2fd37726be481b5ff5;
        tv[56]= 384'h40c318455abf0dc1ee3e4518d7d12070819a0e58f0648a679bfd65facd8c274e1943aef2f85c19235f9adf6027a35dee;
        tv[57]= 384'h9eb6aedbb12730f5bcbe0ad0b4eb19cc3d30406c6b035bfc1a0b91690e29c31d4186c4e2de353e1bbd08f6d07e039cf7;
        tv[58]= 384'h59279f6c4d1a030deb47f3e3b628eb9c98c5558bf5f3020bb57b96890f81390efe43870f894740ce84d68a5c9374b9ff;
        tv[59]= 384'h89ecb85e715fcbb50c49ab574be2be9ce107c8a5eb255c44f3afd78a3042cfb5ae402074ec13e91c0bee072d2a4c9749;
        tv[60]= 384'h26a2997812b25a5794fbc80f0b4b46fbcb7cfc4508169f12313d82f0a558253ca3fe1a8ad0e095466f03710968b999d6;
        tv[61]= 384'h6a827489e2fd495b5cd526f8536fc075391d50d2afa899a4c53a70b3ab147ed28a4ac3ec798d09992c4c64158c6e1c31;
        tv[62]= 384'h1abd1df466ee42591a3ca05d7f3bc1d9f795c861f794137065cbd9df3b31dad1f97324ab19e9677bbd743128f08178c8;
        tv[63]= 384'h18e9805a98e471f95371df85bd049966157dcfbeed1ade00e57fb089761db2d4f85cbd223b0e73fd872286230db3c3b5;

        // Reset wb slave
        wb_rst_i = 1;
        #2;
        wb_rst_i = 0;
        #2;

        // Reset core
        write(CTRL_ADDR, 32'h00000000);
        #2;
        write(CTRL_ADDR, 32'h00000001);

        // Iterate through addresses
        for(addr=0; addr < 16; addr += 4) begin
            if (addr == 0) test_data = 32'h00000003;
            else test_data = TEST_DATA;
            write (addr, test_data);
            #2;
            read (addr);
            if (wb_dat_o !== test_data) begin
                $display("Address: %x", addr);
                $display("Expected: %b", test_data);
                $display("Received: %b", wb_dat_o[31:0]);
                $display("Monitor: r/w failed.");
                $finish;
            end else begin
                $display("Monitor: r/w succeeded.");
            end
        end


        // Test Encryption
        for(tv_it=0; tv_it < 64; tv_it++) begin
            write(CTRL_ADDR, 32'h00000000);
            #2;
            write(CTRL_ADDR, 32'h00000001);
            write(ENC_KEY_4, tv[tv_it][383:352]);
            write(ENC_KEY_3, tv[tv_it][351:320]);
            write(ENC_KEY_2, tv[tv_it][319:288]);
            write(ENC_KEY_1, tv[tv_it][287:256]);
            write(ENC_TXT_4, tv[tv_it][255:224]);
            write(ENC_TXT_3, tv[tv_it][223:192]);
            write(ENC_TXT_2, tv[tv_it][191:160]);
            write(ENC_TXT_1, tv[tv_it][159:128]);
            write(CTRL_ADDR, 32'h00000003);
            #2
            write(CTRL_ADDR, 32'h00000001);
            #120;

            // Check for done signal
            read(CTRL_ADDR);
            if (wb_dat_o[2] == 0) begin
                $display("enc done signal was not set correctly.");
                $finish;
            end

            // Read Results
            read(ENC_TXT_4);
            ciph[127:96] = wb_dat_o[31:0];

            read(ENC_TXT_3);
            ciph[95:64] = wb_dat_o[31:0];

            read(ENC_TXT_2);
            ciph[63:32] = wb_dat_o[31:0];

            read(ENC_TXT_1);
            ciph[31:0] = wb_dat_o[31:0];

            if (ciph !== tv[tv_it][127:0]) begin
                $display("Expected: bcbf217cb280cf30b2517052193ab979");
                $display("Received: %x", ciph);
                $display("Monitor: enc failed.");
                $finish;
            end else begin
                $display("Monitor: enc succeeded.");
            end
        end

        $display("Success!");
        $finish;
    end

    integer i;

    reg [31:0] data;

    task write;
        input [32:0] addr;
        input [32:0] data;
        begin
            @(posedge wb_clk_i) begin
                wb_stb_i = 1;
                wb_cyc_i = 1;
                wb_sel_i = 4'hF;
                wb_we_i = 1;
                wb_adr_i = addr;
                wb_dat_i = data;
                //$display("Write Cycle Started.");
            end
            // Wait for an ACK
            wait(wb_ack_o == 1);
            wait(wb_ack_o == 0);
            wb_cyc_i = 0;
            wb_stb_i = 0;
            //$display("Write Cycle Ended.");
        end
    endtask

    task read;
        input [32:0] addr;
        begin
            @(posedge wb_clk_i) begin
                wb_stb_i = 1;
                wb_cyc_i = 1;
                wb_we_i = 0;
                wb_adr_i = addr;
                //$display("Read Cycle Started.");
            end
            // Wait for an ACK
            wait(wb_ack_o == 1);
            wait(wb_ack_o == 0);
            wb_cyc_i = 0;
            wb_stb_i = 0;
            //$display("Read Cycle Ended.");
        end
    endtask

    wire zw;
    reg[63:0] la_in;
    wire[63:0] la_out;
    aes_core slave(

        .wb_clk_i(wb_clk_i),
        .wb_rst_i(wb_rst_i),
        .wbs_stb_i(wb_stb_i),
        .wbs_cyc_i(wb_cyc_i),
        .wbs_sel_i(wb_sel_i),
        .wbs_we_i(wb_we_i),
        .wbs_dat_i(wb_dat_i),
        .wbs_adr_i(wb_adr_i),
        .wbs_ack_o(wb_ack_o),
        .wbs_dat_o(wb_dat_o),

        .la_data_in(la_in),
        .la_data_out(la_out),
        .la_oenb(la_in)
    );

endmodule
