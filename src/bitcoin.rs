use num_bigint::BigInt;
use num_traits::ops::bytes;

pub fn encode_compact_size(number: u64) -> Vec<u8> {

    let mut leading: &str = "";
    let mut num_of_bytes: i32 = 1;

    if number > 252 && number <= 65535 {
        leading = "FD";
        num_of_bytes = 2;
    } else if number < 65535 && number <= 4294967295 {
        leading = "FE";
        num_of_bytes = 4;
    } else if  number > 4294967295 {
        leading = "FF";
        num_of_bytes = 8;
    }

    let compact_number: Vec<u8> = hex::decode(leading).unwrap();
    let joao = number;
    println!("{:?}", compact_number);
    println!("{:?}", joao);


    return [].to_vec();
}


