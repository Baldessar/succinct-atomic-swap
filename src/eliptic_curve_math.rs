
use std::vec;

use num_bigint_dig::ModInverse;
use bitcoin::secp256k1::{Scalar, constants::{CURVE_ORDER, FIELD_SIZE, GENERATOR_X, GENERATOR_Y}};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::secp256k1::hashes::{sha256, Hash};
use bitcoin::secp256k1;
use num_bigint::BigInt;
use num_traits::{Euclid, Zero};

#[derive(Clone)]
#[derive(PartialEq)]
#[derive(Debug)]
pub struct Point {
    pub x: Vec<u8>,
    pub y: Vec<u8>
}





pub fn double(point: &Point) -> Point{
    let p: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &FIELD_SIZE);

    let point_x: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &point.x);
    let point_y: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &point.y);


    let mut y_modinverse: BigInt = BigInt::from(0);

    match (&point_y * BigInt::from(2)).modinv(&p) {
        Some(inverse) => {y_modinverse = inverse;}
        None => println!("Inverse does not exist for {} mod {}", point_y, p),
    }


    let slope: BigInt = (3 * &point_x.pow(2)) * y_modinverse;

    let x: BigInt = &slope.pow(2) - (2*&point_x);
    let x: BigInt = x.rem_euclid(&p);

    let y: BigInt = &slope * (&point_x - &x) - &point_y;
    let y: BigInt = y.rem_euclid(&p);


    return Point { x: x.to_bytes_be().1, y: y.to_bytes_be().1};

}

pub fn add(point_1: &Point, point_2: &Point) -> Point {

    if point_1 == point_2 {
        return double(point_1);
    }

    let p: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &FIELD_SIZE);

    let x1: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &point_1.x);
    let y1: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &point_1.y);

    let x2: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &point_2.x);
    let y2: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &point_2.y);


    let mut x1_x2_modinverse = BigInt::from(0);

    match BigInt::from(&x1 - &x2).modinv(&p) {
        Some(inverse) => x1_x2_modinverse = inverse,
        None => println!("Inverse does not exist for {} mod {}", (&x1 - &x2), p),
    }

    let slope: BigInt = ((&y1 - &y2) * x1_x2_modinverse).rem_euclid(&p);

    let x: BigInt = (slope.pow(2) - &x1 - &x2).rem_euclid(&p);
    let y: BigInt = ((slope * (&x1-&x)) - &y1).rem_euclid(&p);

    return Point { x: x.to_bytes_be().1.to_vec(), y: y.to_bytes_be().1.to_vec() };


}

pub fn multiply(point: &Point, scalar: &BigInt) -> Point {
    let mut current_point: Point = point.clone();
    for bit  in scalar.to_str_radix(2).chars().skip(1) {
        current_point = double(&current_point);

        if bit == '1' {
            current_point = add(&current_point, point);
        }
    }
    return current_point;

}   


pub fn get_y_from_x(x_hex: &str) -> Point {

    let prefix = &x_hex[..2];
    let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, &hex::decode(&x_hex[2..]).unwrap());


    let p: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &FIELD_SIZE);


    let y_sq = ((x.pow(3)) + BigInt::from(7)).rem_euclid(&p);

    let mut y = y_sq.modpow(&((&p+BigInt::from(1))/BigInt::from(4)), &p);


    if "02" == prefix && y.rem_euclid(&BigInt::from(2)) != BigInt::zero() {
        y = (&p - y).rem_euclid(&p)
    }

    if "03" == prefix && y.rem_euclid(&BigInt::from(2)) == BigInt::zero() {
        y = (&p - y).rem_euclid(&p)
    }

    return Point { x: x.to_bytes_be().1, y: y.to_bytes_be().1};
}
