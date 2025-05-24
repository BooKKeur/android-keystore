use crate::{AttachGuard, JClass, JObject, Object};

pub struct KeyPair<'a> {
    pub inner: JObject<'a>,
}

pub struct PublicKey<'a> {
    pub inner: JObject<'a>,
}

pub struct PrivateKey<'a> {
    pub inner: JObject<'a>,
}

impl<'a> KeyPair<'a> {
    pub fn get_public(&self, env: &mut AttachGuard<'a>) -> jni::errors::Result<PublicKey<'a>> {
        Ok(PublicKey {
            inner: env
                .call_method(&self.inner, "getPublic", "()Ljava/security/PublicKey;", &[])
                .unwrap()
                .l()?,
        })
    }

    pub fn get_private(&self, env: &mut AttachGuard<'a>) -> jni::errors::Result<PrivateKey<'a>> {
        Ok(PrivateKey {
            inner: env
                .call_method(
                    &self.inner,
                    "getPrivate",
                    "()Ljava/security/PrivateKey;",
                    &[],
                )
                .unwrap()
                .l()?,
        })
    }
}

impl<'a> Object<'a> for KeyPair<'a> {
    fn class(env: &mut AttachGuard<'a>) -> JClass<'a> {
        env.find_class("java/security/KeyPair")
            .expect("Failed to find KeyPair class")
    }

    fn l(&self) -> &JObject<'a> {
        &self.inner
    }
}

impl<'a> Object<'a> for PublicKey<'a> {
    fn class(env: &mut AttachGuard<'a>) -> JClass<'a> {
        env.find_class("java/security/PublicKey")
            .expect("Failed to find PublicKey class")
    }

    fn l(&self) -> &JObject<'a> {
        &self.inner
    }
}

impl<'a> Object<'a> for PrivateKey<'a> {
    fn class(env: &mut AttachGuard<'a>) -> JClass<'a> {
        env.find_class("java/security/PrivateKey")
            .expect("Failed to find PrivateKey class")
    }

    fn l(&self) -> &JObject<'a> {
        &self.inner
    }
}
