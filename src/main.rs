use bson::{doc, Bson};
use bytes::Buf;
use libaes::Cipher;
use rand::{thread_rng, RngCore};
use rsa::{RsaPublicKey, PublicKey, PaddingScheme, pkcs8::DecodePublicKey};
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use tokio::{net::TcpStream, io::{BufStream, AsyncWriteExt, AsyncReadExt}};
use tokio_native_tls::{native_tls};
use tokio_util::compat::TokioAsyncReadCompatExt;

#[derive(Serialize, Deserialize, Debug)]
struct ConnectionInfo {
    #[serde(rename = "bgKeepItv")]
    background_keep_interval: i32,
    #[serde(rename = "bgReconnItv")]
    background_reconnect_interval: i32,
    #[serde(rename = "bgPingItv")]
    background_interval: i32,
    #[serde(rename = "fgPingItv")]
    ping_interval: i32,
    #[serde(rename = "reqTimeout")]
    request_timeout: i32,
    #[serde(rename = "encType")]
    encrypt_type: i32,
    #[serde(rename = "connTimeout")]
    connection_timeout: i32,
    #[serde(rename = "recvHeaderTimeout")]
    receive_header_timeout: i32,
    #[serde(rename = "inSegTimeout")]
    in_seg_timeout: i32,
    #[serde(rename = "outSegTimeout")]
    out_seg_timeout: i32,
    #[serde(rename = "blockSendBufSize")]
    block_send_buffer_size: i32,
    ports: Vec<i32>
}

#[derive(Serialize, Deserialize, Debug)]
struct HostInfo {
    ssl: Vec<String>,
    v2sl: Vec<String>,
    lsl: Vec<String>,
    lsl6: Vec<String>
}

#[derive(Serialize, Deserialize, Debug)]
struct Trailer {
    #[serde(rename = "tokenExpireTime")]
    token_expire_time: i32,
    resolution: i32,
    #[serde(rename = "resolutionHD")]
    resolution_hd: i32,
    #[serde(rename = "compRatio")]
    compress_ratio: i8,
    #[serde(rename = "compRatioHD")]
    compress_ratio_hd: i8,
    #[serde(rename = "downMode")]
    down_mode: i8,
    #[serde(rename = "concurrentDownLimit")]
    concurrent_down_limit: i16,
    #[serde(rename = "concurrentUpLimit")]
    concurrent_up_limit: i16,
    #[serde(rename = "maxRelaySize")]
    max_relay_size: i32,
    #[serde(rename = "downCheckSize")]
    down_check_size: i32,
    #[serde(rename = "upMaxSize")]
    up_max_size: i32,
    #[serde(rename = "videoUpMaxSize")]
    video_up_max_size: i32,
    #[serde(rename = "vCodec")]
    video_codec: i8,
    #[serde(rename = "vFps")]
    video_fps: i16,
    #[serde(rename = "aCodec")]
    audio_codec: i8,
    #[serde(rename = "contentExpireTime")]
    content_expire_time: i32,
    #[serde(rename = "vResolution")]
    video_resolution: i32,
    #[serde(rename = "vBitrate")]
    video_bitrate: i32,
    #[serde(rename = "aFrequency")]
    audio_frequency: i32
}

#[derive(Serialize, Deserialize, Debug)]
struct TrailerH {
    #[serde(rename = "vResolution")]
    video_resolution: i32,
    #[serde(rename = "vBitrate")]
    video_bitrate: i32,
    #[serde(rename = "aFrequency")]
    audio_frequency: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct GetConfRes {
    revision: i32,
    #[serde(rename = "3g")]
    ceullar: ConnectionInfo,
    wifi: ConnectionInfo,
    ticket: HostInfo,
    trailer: Trailer,
    #[serde(rename = "trailer.h")]
    trailer_high: TrailerH
}

#[derive(Serialize, Deserialize, Debug)]
struct CheckinResponse {
    #[serde(rename = "cacheExpire")]
    cache_expire: u32,
    cshost: String,
    cshost6: String,
    csport: u32,
    host: String,
    host6: String,
    port: u32,
    status: u32,
    vsshost: String,
    vsshost6: String,
    vssport: u32,
}

struct RequestLocoHeader {
    packet_id: u32,
    status_code: u16,
    method_name: String,
    body_type: u8
}

#[derive(Serialize, Deserialize, Debug)]
struct RawLocoHeader {
    packet_id: u32,
    status_code: u16,
    method_name: [u8; 11],
    body_type: u8,
    body_length: u32
}

#[derive(Debug)]
struct ResponseLocoHeader {
    packet_id: u32,
    status_code: u16,
    method_name: String,
    body_type: u8,
    body_length: u32
}

#[derive(Serialize, Deserialize, Debug)]
struct LocoHandshakeHeader {
    data_length: u32,
    rsa_encrypt_type: u32,
    aes_encrypt_type: u32
}

#[derive(Serialize, Deserialize, Debug)]
struct CheckinRequest {
    #[serde(rename="userId")]
    user_id: i64,
    os: String,
    ntype: u16,
    #[serde(rename="appVer")]
    app_ver: String,
    lang: String,
    #[serde(rename="MCCMNC")]
    mccmnc: String
}

#[derive(Serialize, Deserialize, Debug)]
struct LocoSecureHeader {
    data_length: u32,
    iv_key: [u8; 16],
}

#[derive(Serialize, Deserialize, Debug)]
struct BookingRequest {
    model: String,
    os: String,
    #[serde(rename="MCCMNC")]
    mccmnc: String
}

struct ResponseLocoPacket<T> {
    header: ResponseLocoHeader, // TODO: LocoHeader로 분리
    body: T
}

fn parse_loco_header(header_buffer: &[u8]) -> ResponseLocoHeader {
    let raw_header: RawLocoHeader = bincode::deserialize(header_buffer).unwrap();
    let method_name = String::from_utf8(raw_header.method_name.to_vec()).unwrap().replace("\0", "");
    let response_header = ResponseLocoHeader {
        packet_id: raw_header.packet_id,
        status_code: raw_header.status_code,
        method_name: method_name,
        body_type: raw_header.body_type,
        body_length: raw_header.body_length
    };

    response_header
}

fn parse_loco_packet<T: DeserializeOwned>(header_buffer: &[u8], data_buffer: &[u8]) -> ResponseLocoPacket<T> {
    let response_header = parse_loco_header(header_buffer);
    let body: T = bson::from_bson(bson::Bson::Document(bson::from_slice(&*data_buffer).unwrap())).unwrap();

    ResponseLocoPacket {
        header: response_header,
        body
    }
}

fn create_loco_raw_header(header: RequestLocoHeader, body_length: u32) -> RawLocoHeader {
    let raw_loco_header = RawLocoHeader {
        packet_id: header.packet_id,
        status_code: header.status_code,
        method_name: (&*[header.method_name.as_bytes(), &([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..(11 - header.method_name.len())])].concat())[..11].try_into().unwrap(),
        body_type: header.body_type,
        body_length: body_length
    };

    raw_loco_header
}

fn create_loco_packet(header: RequestLocoHeader, body: Bson) -> Vec<u8> {
    let body_vec = bytes::BytesMut::from(&*bson::to_vec(&body).unwrap());
    let raw_loco_header = create_loco_raw_header(header, body_vec.len() as u32);
    let loco_header_vec = bincode::serialize(&raw_loco_header).unwrap();

    [loco_header_vec, body_vec.to_vec()].concat()
}

async fn get_booking_data() {
    let connector = tokio_native_tls::TlsConnector::from(native_tls::TlsConnector::new().unwrap());
    let connection = connector
        .connect(
            "booking-loco.kakao.com",
            BufStream::new(
                TcpStream::connect("booking-loco.kakao.com:443")
                    .await.unwrap(),
            )
        )
        .await.unwrap()
        .compat();

    let mut stream = connection.into_inner();
    let request_buffer = create_loco_packet(
        RequestLocoHeader {
            packet_id: 1,
            status_code: 0,
            method_name: "GETCONF".to_string(),
            body_type: 0
        }, bson::to_bson(&BookingRequest {
            model: "".to_string(),
            os: "".to_string(),
            mccmnc: "".to_string()
        }).unwrap());

    stream.write(&request_buffer).await.unwrap();
    stream.flush().await.unwrap();

    let mut header_buffer = [0; 22];
    stream.read_exact(&mut header_buffer).await.unwrap();
    let loco_header = parse_loco_header(&header_buffer);

    let mut data_buffer = vec![0; loco_header.body_length.try_into().unwrap()];
    stream.read_exact(&mut data_buffer).await.unwrap();

    let response_packet = parse_loco_packet::<GetConfRes>(&header_buffer, &data_buffer);
    println!("{:?} {:?}", response_packet.header, response_packet.body);;
}

async fn get_checkin_data() {
    let mut stream = TcpStream::connect("ticket-loco.kakao.com:443").await.unwrap();
    let mut rng = thread_rng();

    let mut aes_key = [0; 16];
    rng.fill_bytes(&mut aes_key);

    let pem_key = "-----BEGIN PUBLIC KEY-----\nMIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA52Y1NVBfNkzCmnggwVwScdUO7enyo/RtnSsr8io+8cQrhXlsi1Msn8yGQv+JW9AZKyetYeYl/BuCFS7liJixwJ1UFkH7J0m8GRGNH4VRuRMJa97WfvVpsMr1cIaFnoCeRwvvaaqw9/ikWFWw/Cq6ieAsO80pRCcAVh1mCytDUmeqykuz6TYwldTaYbpHO8u48d3jvUXveSv5J9t40GiaMdyVRZpx7LY2M0ZsjjbQXRe8ziXtGEq/8Gk0vkV2BnRk/v6uce8k5ERCWGyVHRaRo6FJljYNvaIoBBx2WGJVbb6fXCLlkPFlH/A9tGZ0fxNDuomZWwnF+EDIDsq5R/G8+wIBAw==\n-----END PUBLIC KEY-----";
    let pub_key = RsaPublicKey::from_public_key_der(&pem::parse(pem_key).unwrap().contents).unwrap();
    let encrypted_aes_key = pub_key.encrypt(&mut rng, PaddingScheme::new_oaep::<sha1::Sha1>(), &aes_key).unwrap().to_vec();
    let handshake_packet = LocoHandshakeHeader { data_length: encrypted_aes_key.len() as u32, rsa_encrypt_type: 14, aes_encrypt_type: 2 };
    let handshake_buffer = [bincode::serialize(&handshake_packet).unwrap(), encrypted_aes_key].concat();

    stream.write(&handshake_buffer).await.unwrap();
    stream.flush().await.unwrap();

    let request_buffer = create_loco_packet(
        RequestLocoHeader {
            packet_id: 1,
            status_code: 0,
            method_name: "CHECKIN".to_string(),
            body_type: 0
        }, bson::to_bson(&CheckinRequest {
            user_id: 1,
            os: "android".to_string(),
            ntype: 0,
            app_ver: "9.7.2".to_string(),
            lang: "ko".to_string(),
            mccmnc: "45005".to_string()
        }).unwrap());

    let aes_cipher = Cipher::new_128(&aes_key);
    let mut iv_key = [0; 16];
    rng.fill_bytes(&mut iv_key);

    let encrypted_aes_data = aes_cipher.cfb128_encrypt(&iv_key, &request_buffer);
    let secure_data_length = (encrypted_aes_data.len() + 16) as u32;
    let secure_packet = LocoSecureHeader { data_length: secure_data_length, iv_key };
    let secure_buffer = [bincode::serialize(&secure_packet).unwrap(), encrypted_aes_data].concat();
    
    stream.write(&secure_buffer).await.unwrap();    
    stream.flush().await.unwrap();

    let mut header_buffer = [0; 20];
    stream.read_exact(&mut header_buffer).await.unwrap();

    let mut bytes = bytes::BytesMut::from(&header_buffer[..]);
    let size = bytes.get_u32_le() as usize - 16;
    let mut data_buffer = vec![0; size];
    stream.read_exact(&mut data_buffer).await.unwrap();
    
    let decrypted_buffer = aes_cipher.cfb128_decrypt(&header_buffer[4..20], &data_buffer);
    let header_buffer = &decrypted_buffer[0..22];
    let data_buffer = &decrypted_buffer[22..];

    let response_packet = parse_loco_packet::<CheckinResponse>(header_buffer, data_buffer);
    println!("{:?} {:?}", response_packet.header, response_packet.body);
}

#[tokio::main]
async fn main() {
    get_booking_data().await;
    get_checkin_data().await;
}