use std::io;

use libp2p::futures::{AsyncWrite, AsyncWriteExt};
use snap::read::FrameEncoder;

use crate::messages::encode_varint;

pub async fn write_payload<T>(io: &mut T, encoded: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    let mut compressor = FrameEncoder::new(encoded);

    let mut buf = Vec::new();
    io::Read::read_to_end(&mut compressor, &mut buf)?;

    let mut size_buf = [0; 5];
    let varint_buf = encode_varint(buf.len() as u32, &mut size_buf);
    io.write_all(varint_buf).await?;
    io.write_all(&buf).await?;

    Ok(())
}
