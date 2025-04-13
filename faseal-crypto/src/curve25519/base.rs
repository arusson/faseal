// FaSEAL, a simple tool for encrypted archives
// Copyright (C) 2025 A. Russon
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::curve25519::{
    field::Fe,
    points::Point
};

impl Point {
    pub(crate) const BASE_PRECOMP: [Point; 8] = [
        Point {
            x: Fe {
                buf: [
                    1738742601995546,
                    1146398526822698,
                    2070867633025821,
                    562264141797630,
                    587772402128613,
                ],
            },
            y: Fe {
                buf: [
                    1801439850948184,
                    1351079888211148,
                    450359962737049,
                    900719925474099,
                    1801439850948198,
                ],
            },
            z: Fe {
                buf: [1, 0, 0, 0, 0],
            },
            t: Fe {
                buf: [
                    1841354044333475,
                    16398895984059,
                    755974180946558,
                    900171276175154,
                    1821297809914039,
                ],
            },
        },
        Point {
            x: Fe {
                buf: [
                    1584731938606606,
                    178923850428536,
                    228280466683449,
                    622454613327500,
                    961744189650336,
                ],
            },
            y: Fe {
                buf: [
                    2048039769908169,
                    611908456202699,
                    1838921828590653,
                    1373353662182500,
                    604786679386674,
                ],
            },
            z: Fe {
                buf: [1, 0, 0, 0, 0],
            },
            t: Fe {
                buf: [
                    632586093835265,
                    343317749454563,
                    1142187722401459,
                    1246910387029049,
                    643809026290422,
                ],
            },
        },
        Point {
            x: Fe {
                buf: [
                    642526368817756,
                    897391692666252,
                    962214031593056,
                    2151263124273695,
                    1823994305194280,
                ],
            },
            y: Fe {
                buf: [
                    959085406434516,
                    823416103927896,
                    169856804346800,
                    1360991708301104,
                    323785187622630,
                ],
            },
            z: Fe {
                buf: [1, 0, 0, 0, 0],
            },
            t: Fe {
                buf: [
                    291346836595738,
                    421537610553791,
                    1939901930052822,
                    712990200152534,
                    744163847642585,
                ],
            },
        },
        Point {
            x: Fe {
                buf: [
                    745845847357552,
                    55498538281255,
                    233662937943675,
                    179502033034301,
                    567187168652543,
                ],
            },
            y: Fe {
                buf: [
                    188436492456239,
                    1791404585917415,
                    938732500011168,
                    827535094727360,
                    1263401179066713,
                ],
            },
            z: Fe {
                buf: [1, 0, 0, 0, 0],
            },
            t: Fe {
                buf: [
                    2008766715925336,
                    1080663717006321,
                    546068614240140,
                    851266986915171,
                    606396996224818,
                ],
            },
        },
        Point {
            x: Fe {
                buf: [
                    172349289591347,
                    2014045392908840,
                    1326661600583783,
                    1194063046802408,
                    1301660503301685,
                ],
            },
            y: Fe {
                buf: [
                    597601052707053,
                    370708851696154,
                    1769224146297019,
                    2031829141359172,
                    1676215595929578,
                ],
            },
            z: Fe {
                buf: [1, 0, 0, 0, 0],
            },
            t: Fe {
                buf: [
                    370247452852688,
                    175926773542019,
                    1366829968581946,
                    1871474830157891,
                    2047038905238931,
                ],
            },
        },
        Point {
            x: Fe {
                buf: [
                    690607081910845,
                    85278329204487,
                    1170597539714662,
                    15605081464942,
                    1347423509652566,
                ],
            },
            y: Fe {
                buf: [
                    697987907550964,
                    231488761894970,
                    1475501116163568,
                    1214474405336062,
                    93313529186413,
                ],
            },
            z: Fe {
                buf: [1, 0, 0, 0, 0],
            },
            t: Fe {
                buf: [
                    1925007367139794,
                    720797401577721,
                    2145641378528840,
                    43711000824999,
                    1059031511767718,
                ],
            },
        },
        Point {
            x: Fe {
                buf: [
                    1574616431476999,
                    1820233879956234,
                    1255659963129895,
                    1872970577808549,
                    357789706735435,
                ],
            },
            y: Fe {
                buf: [
                    1342184246764216,
                    245145966977624,
                    1366370960941229,
                    729817606665326,
                    875581666407549,
                ],
            },
            z: Fe {
                buf: [1, 0, 0, 0, 0],
            },
            t: Fe {
                buf: [
                    1483611988028699,
                    1481949820256791,
                    2065891370619276,
                    1985503051571908,
                    309956969615717,
                ],
            },
        },
        Point {
            x: Fe {
                buf: [
                    2249308877718728,
                    2093526803490672,
                    346613787454233,
                    240935905963644,
                    1816591146253687,
                ],
            },
            y: Fe {
                buf: [
                    2071110476085684,
                    2124547928253381,
                    611114757251315,
                    488970596615347,
                    595043560496727,
                ],
            },
            z: Fe {
                buf: [1, 0, 0, 0, 0],
            },
            t: Fe {
                buf: [
                    1957245925085631,
                    1590484463955447,
                    790988240438073,
                    1531117259804060,
                    779509163810686,
                ],
            },
        },
    ];
}
