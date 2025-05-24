use jni::{AttachGuard, objects::JClass};

use crate::{JNIString, JObject, JValue, Object, utils::make_string_array};

#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum Purpose {
    Encrypt = 1,
    Decrypt = 2,
    Sign = 4,
    Verify = 8,
    WrapKey = 32,
    AgreeKey = 64,
    AttestKey = 128,
}

pub enum Digest {
    None,
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl From<&Digest> for JNIString {
    fn from(val: &Digest) -> Self {
        match val {
            Digest::None => "NONE".into(),
            Digest::Md5 => "MD5".into(),
            Digest::Sha1 => "SHA-1".into(),
            Digest::Sha224 => "SHA-224".into(),
            Digest::Sha256 => "SHA-256".into(),
            Digest::Sha384 => "SHA-384".into(),
            Digest::Sha512 => "SHA-512".into(),
        }
    }
}

pub enum Padding {
    None,
    Pkcs7,
    RsaOaep,
    RsaPkcs1,
}

impl From<&Padding> for JNIString {
    fn from(val: &Padding) -> Self {
        match val {
            Padding::None => "NoPadding".into(),
            Padding::Pkcs7 => "PKCS7Padding".into(),
            Padding::RsaOaep => "OAEPPadding".into(),
            Padding::RsaPkcs1 => "PKCS1Padding".into(),
        }
    }
}

#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum AuthType {
    DeviceCredential = 1,
    BiometricStrong = 2,
}

pub struct KeyGenParameterSpec<'a> {
    pub inner: JObject<'a>,
}

pub struct Builder<'a> {
    pub inner: JObject<'a>,
}

impl<'a> Builder<'a> {
    pub fn new<S>(alias: S, purposes: &[Purpose], env: &mut AttachGuard<'a>) -> Self
    where
        S: Into<JNIString>,
    {
        let alias_str = env
            .new_string(alias)
            .expect("Failed to create alias string");

        let purposes: i32 = purposes.iter().fold(0, |acc, p| acc | *p as i32);

        Self {
            inner: env
                .new_object(
                    "android/security/keystore/KeyGenParameterSpec$Builder",
                    "(Ljava/lang/String;I)V",
                    &[JValue::Object(&alias_str), JValue::Int(purposes)],
                )
                .expect("Failed to call new on KeyGenParameterSpec.Builder class"),
        }
    }

    pub fn set_digests(self, digests: &'a [Digest], env: &mut AttachGuard<'a>) -> Self {
        let string_array = make_string_array(digests, env);

        Self {
            inner: env
                .call_method(
                    self.inner,
                    "setDigests",
                    "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                    &[JValue::Object(&string_array)],
                )
                .expect("Failed to call setDigests method")
                .l()
                .expect("Failed to get JObject"),
        }
    }

    pub fn set_encryption_paddings(
        self,
        paddings: &'a [Padding],
        env: &mut AttachGuard<'a>,
    ) -> Self {
        let string_array = make_string_array(paddings, env);

        Self {
            inner: env
                .call_method(
                    self.inner,
                    "setEncryptionPaddings",
                    "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                    &[JValue::Object(&string_array)],
                )
                .expect("Failed to call setEncryptionPaddings method")
                .l()
                .expect("Failed to get JObject"),
        }
    }

    pub fn set_user_authentication_parameters(
        self,
        timeout: usize,
        auth_type: &[AuthType],
        env: &mut AttachGuard<'a>,
    ) -> Self {
        Self {
            inner: env
                .call_method(
                    self.inner,
                    "setUserAuthenticationParameters",
                    "(II)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                    &[
                        JValue::Int(timeout as i32),
                        JValue::Int(auth_type.iter().fold(0, |acc, p| acc | *p as i32)),
                    ],
                )
                .expect("Failed to call setUserAuthenticationParameters method")
                .l()
                .expect("Failed to get JObject"),
        }
    }

    pub fn set_user_authentication_required(
        self,
        required: bool,
        env: &mut AttachGuard<'a>,
    ) -> Self {
        Self {
            inner: env
                .call_method(
                    self.inner,
                    "setUserAuthenticationRequired",
                    "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                    &[JValue::Bool(required as u8)],
                )
                .expect("Failed to call setUserAuthenticationRequired method")
                .l()
                .expect("Failed to get JObject"),
        }
    }

    pub fn build(self, env: &mut AttachGuard<'a>) -> KeyGenParameterSpec<'a> {
        KeyGenParameterSpec {
            inner: env
                .call_method(
                    self.inner,
                    "build",
                    "()Landroid/security/keystore/KeyGenParameterSpec;",
                    &[],
                )
                .expect("Failed to call build method")
                .l()
                .expect("Failed to get JObject"),
        }
    }
}

impl<'a> Object<'a> for Builder<'a> {
    fn class(env: &mut AttachGuard<'a>) -> JClass<'a> {
        env.find_class("android/security/keystore/KeyGenParameterSpec$Builder")
            .expect("Failed to find KeyGenParameterSpec$Builder class")
    }

    fn l(&self) -> &JObject<'a> {
        &self.inner
    }
}
