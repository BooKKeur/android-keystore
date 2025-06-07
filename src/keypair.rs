use base64::Engine;
use jni::objects::{JByteArray, JValue};

use crate::{AttachGuard, JClass, JObject, Object, keypair_generator::Algorithm};

#[derive(Debug)]
pub struct KeyPair<'a>(JObject<'a>);

impl<'a> From<JObject<'a>> for KeyPair<'a> {
    fn from(value: JObject<'a>) -> Self {
        Self(value)
    }
}

#[derive(Debug)]
pub struct PublicKey<'a>(JObject<'a>);

impl<'a> From<JObject<'a>> for PublicKey<'a> {
    fn from(value: JObject<'a>) -> Self {
        Self(value)
    }
}

#[derive(Debug)]
pub struct PrivateKey<'a>(JObject<'a>);

impl<'a> From<JObject<'a>> for PrivateKey<'a> {
    fn from(value: JObject<'a>) -> Self {
        Self(value)
    }
}
impl<'a> KeyPair<'a> {
    pub fn get_public(&self, env: &mut AttachGuard<'a>) -> jni::errors::Result<PublicKey<'a>> {
        Ok(env
            .call_method(self.l(), "getPublic", "()Ljava/security/PublicKey;", &[])
            .unwrap()
            .l()?
            .into())
    }

    pub fn get_private(&self, env: &mut AttachGuard<'a>) -> jni::errors::Result<PrivateKey<'a>> {
        Ok(env
            .call_method(self.l(), "getPrivate", "()Ljava/security/PrivateKey;", &[])
            .unwrap()
            .l()?
            .into())
    }
}

impl<'a> Object<'a> for KeyPair<'a> {
    fn class(env: &mut AttachGuard<'a>) -> JClass<'a> {
        env.find_class("java/security/KeyPair")
            .expect("Failed to find KeyPair class")
    }

    fn l(&self) -> &JObject<'a> {
        &self.0
    }
}

impl<'a> PublicKey<'a> {
    pub fn get_decoded(&self, env: &mut AttachGuard<'a>) -> String {
        let public_key_bytes: JByteArray<'_> = env
            .call_method(self.l(), "getEncoded", "()[B", &[])
            .expect("Failed to call getEncoded")
            .l()
            .expect("Failed to get byte array")
            .into();

        let public_key_bytes = env
            .convert_byte_array(public_key_bytes)
            .expect("Failed to convert byte array");

        let engine: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
        engine.encode(public_key_bytes)
    }

    pub fn from_x509_string(
        str: impl Into<String>,
        algorithm: Algorithm,
        env: &mut AttachGuard<'a>,
    ) -> Self {
        let engine: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
        let bytes = engine.decode(str.into()).expect("Failed to decode string");

        let java_byte_array = env
            .new_byte_array(bytes.len() as i32)
            .expect("Failed to create byte array");

        env.set_byte_array_region(
            &java_byte_array,
            0,
            bytes
                .iter()
                .map(|b| *b as i8)
                .collect::<Vec<i8>>()
                .as_slice(),
        )
        .expect("Failed to set byte array region");

        let key_factory_class = env
            .find_class("java/security/KeyFactory")
            .expect("Failed to find KeyFactory class");

        let algorithm = &env.new_string(&algorithm).expect("Failed to create string");
        let key_factory = env
            .call_static_method(
                key_factory_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyFactory;",
                &[JValue::Object(algorithm)],
            )
            .expect("Failed to create KeyFactory")
            .l()
            .expect("Failed to get Object");

        let spec_public = env
            .new_object(
                "java/security/spec/X509EncodedKeySpec",
                "([B)V",
                &[JValue::Object(&java_byte_array)],
            )
            .expect("Failed to create EncodedKeySpec");

        let key = env.call_method(
            &key_factory,
            "generatePublic",
            "(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;",
            &[JValue::Object(&spec_public)],
        );

        if env.exception_check().expect("Failed to check exception") {
            env.exception_describe()
                .expect("Failed to describe exception");
        }

        let key = key
            .expect("Failed to generate public key")
            .l()
            .expect("Failed to get public key");

        key.into()
    }
}

impl<'a> Object<'a> for PublicKey<'a> {
    fn class(env: &mut AttachGuard<'a>) -> JClass<'a> {
        env.find_class("java/security/PublicKey")
            .expect("Failed to find PublicKey class")
    }

    fn l(&self) -> &JObject<'a> {
        &self.0
    }
}

impl<'a> Object<'a> for PrivateKey<'a> {
    fn class(env: &mut AttachGuard<'a>) -> JClass<'a> {
        env.find_class("java/security/PrivateKey")
            .expect("Failed to find PrivateKey class")
    }

    fn l(&self) -> &JObject<'a> {
        &self.0
    }
}
