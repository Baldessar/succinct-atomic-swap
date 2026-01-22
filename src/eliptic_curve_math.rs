
use std::vec;

use bitcoin::secp256k1::{constants::{CURVE_ORDER, FIELD_SIZE, GENERATOR_X, GENERATOR_Y}};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::secp256k1::hashes::{sha256, Hash};
use bitcoin::secp256k1;
use num_bigint::{BigInt, RandBigInt, ToBigInt};
use num_traits::{Euclid, Zero};

#[derive(Clone)]
#[derive(PartialEq)]
#[derive(Debug)]
pub struct Point {
    pub x: Vec<u8>,
    pub y: Vec<u8>
}

#[derive(Clone)]
#[derive(PartialEq)]
#[derive(Debug)]
pub struct Signature {
    pub r: Vec<u8>,
    pub s: Vec<u8>
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

pub fn pre_sign(message: &Vec<u8>, nonce: &BigInt, statement_t: &Point, prv_key: &SecretKey) -> (BigInt, BigInt, PublicKey, Point, Point){
    let secp: Secp256k1<secp256k1::All> = Secp256k1::new();

    let generator = Point { x: GENERATOR_X.to_vec(), y: GENERATOR_Y.to_vec() };
    let q: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &CURVE_ORDER);
    let pub_key = prv_key.public_key(&secp);

    
    println!("R and R' are shareable nounce values");
    let x_secret: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &prv_key.secret_bytes());
    
    println!("Bob multiplies the nounce K by the generating point, getting R'");
    let r_line_kG = multiply(&generator, &nonce);
    println!("Bob also multiplies the nounce K by T, getting R");
    let r_kT = multiply(statement_t, &nonce);


    println!("Both values R'and R are points on the Elliptic Curve and therefore have x and y coordinates. Because of that Bob can define a value r as the x-coordinate of R.");
    let r: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &r_kT.x);

    println!("Hash the message and interpret the result as a point in the curve");
    let z: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus,sha256::Hash::hash(message).as_byte_array()).rem_euclid(&q);


    println!("As a last step of Pre Signing, bob computes the value s' as the inverse of the nonce k multiplied by the hashed message z which is added to the product of the point r and his secret key x.");
    let s_line: BigInt = (nonce.modinv(&q).unwrap()*(&z + &r*x_secret)).rem_euclid(&q);

    return (r, s_line, pub_key, r_kT, r_line_kG)
}

pub fn pre_verify(message: &Vec<u8>, s_line: &BigInt, r: &BigInt, r_line_kG: Point, pub_key: &PublicKey) -> bool {
    let generator = Point { x: GENERATOR_X.to_vec(), y: GENERATOR_Y.to_vec() };
    let q: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &CURVE_ORDER);

    let xG: Point = get_y_from_x(&pub_key.to_string());

    let message_hash: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus,sha256::Hash::hash(message).as_byte_array()).rem_euclid(&q);
    
    let u: BigInt = (message_hash*&s_line.modinv(&q).unwrap()).rem_euclid(&q);
    let v: BigInt = (r*&s_line.modinv(&q).unwrap()).rem_euclid(&q);

    let uG = multiply(&generator, &u);
    let vX = multiply(&xG, &v);

    let verification_point: Point = add(&uG, &vX);

    return &r_line_kG.x == &verification_point.x && &r_line_kG.y == &verification_point.y;
}


pub fn sign(private_key: &bitcoin::PrivateKey, message: &Vec<u8>, is_test: bool) -> Signature {
// pub fn sign( is_test: bool) {
    let generator: Point = Point { x: GENERATOR_X.to_vec(), y: GENERATOR_Y.to_vec() };
    let mut rng = rand::thread_rng();

    let curve_order: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &CURVE_ORDER);

    let mut actual_nonce: BigInt = 1.to_bigint().expect("");
    
    if !is_test {
        actual_nonce = rng.gen_bigint_range(&0.to_bigint().expect(""),&BigInt::from_bytes_be(num_bigint::Sign::Plus,&CURVE_ORDER))
    }

    let r: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &multiply(&generator, &actual_nonce).x).rem_euclid(&BigInt::from_bytes_be(num_bigint::Sign::Plus,&CURVE_ORDER));

    let s = ((actual_nonce.modinv(&curve_order)).expect("msg") * (BigInt::from_bytes_be(num_bigint::Sign::Plus, &message) + BigInt::from_bytes_be(num_bigint::Sign::Plus, &private_key.to_bytes()) * &r)).rem_euclid(&curve_order);

    return Signature {r: r.to_bytes_be().1.to_vec(), s: s.to_bytes_be().1.to_vec()}
}