use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use nova_snark::{
    // ✅ Bỏ `Group` đi để xóa cảnh báo (warning)
    traits::{circuit::{StepCircuit, TrivialCircuit}, Engine}, 
    provider::{PallasEngine, VestaEngine}, 
    RecursiveSNARK, PublicParams,
};
use pasta_curves::pallas::Scalar as Fr;
// ✅ Thêm `PrimeField` vào đây để gọi được hàm `from_repr`
use ff::{Field, PrimeField}; 
use rand::Rng;
use std::time::Instant;

mod constants;
mod poseidon2_gadget;
use poseidon2_gadget::Poseidon2Gadget;

#[derive(Clone, Debug)]
pub struct DataSector {
    pub id: u64,
    pub data: Vec<u8>,
    pub commitment: Fr,
}

impl DataSector {
    pub fn new(id: u64, data: Vec<u8>) -> Self {
        let mut hasher = blake3::Hasher::new();//tạo bộ băm mới
        hasher.update(&data);//đưa dữ liệu vào bộ băm
        let hash_bytes = hasher.finalize();//lấy kết quả băm dưới dạng 32 bytes
        
        let mut commitment_bytes = [0u8; 32]; //mảng 32 số 0
        commitment_bytes.copy_from_slice(hash_bytes.as_bytes()); // copy 32 byte từ hash vào mảng
        let commitment = Option::from(Fr::from_repr(commitment_bytes)).unwrap_or(Fr::ZERO);//Chuyển 32 byte thành số trong trường hữu hạn (Fr), nếu lỗi thì dùng số 0
        
        Self { id, data, commitment }// Trả về struct mới
    }
}

#[derive(Clone, Debug)]
pub struct PoStStepCircuit {
    pub challenge_random: Fr, // thử thách ngẫu nhiên
    pub sector_commitment: Fr,//hash của dữ liệu
    pub epoch: Fr,//số thứ tự thời gian (epoch)
}

impl StepCircuit<Fr> for PoStStepCircuit {
    fn arity(&self) -> usize { 1 }

    fn synthesize<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<Fr>],
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        
        let z_prev = z_in[0].clone();
        
        let challenge_var = AllocatedNum::alloc(cs.namespace(|| "challenge"), || Ok(self.challenge_random))?;
        let sector_var = AllocatedNum::alloc(cs.namespace(|| "sector"), || Ok(self.sector_commitment))?;
        let epoch_var = AllocatedNum::alloc(cs.namespace(|| "epoch"), || Ok(self.epoch))?;
        
        let combined_data = AllocatedNum::alloc(cs.namespace(|| "combined"), || {
            Ok(self.sector_commitment + self.epoch)
        })?;
        
        cs.enforce(
            || "combine",
            |lc| lc + sector_var.get_variable() + epoch_var.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + combined_data.get_variable(),
        );
        
        let initial_state = vec![z_prev, challenge_var, combined_data];
        let mut hasher = Poseidon2Gadget::new(cs, initial_state);
        let state_out = hasher.hash()?;
        
        Ok(vec![state_out[0].clone()])
    }
}

fn main() {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║     PROOF OF SPACE-TIME (PoSt) WITH NOVA FOLDING SCHEME        ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    
    //khởi tạo dữ liệu
    //let sector: Tạo biến tên sector
    //DataSector::new(): Gọi hàm new của struct DataSector
    //b"...": Byte string literal (kiểu &[u8; 26])
    //.to_vec(): Chuyển thành Vec<u8> (vector các byte)
    let sector = DataSector::new(1, b"Important blockchain data".to_vec()); // ✅ Tạo một sector với dữ liệu mẫu
    let initial_state = Fr::from(12345u64);
    
    //tạo circuit chính (primary circuit) với các tham số ban đầu, bao gồm giá trị ngẫu nhiên cho challenge, cam kết của sector và epoch
    let circuit_primary = PoStStepCircuit {
        challenge_random: Fr::ZERO,
        sector_commitment: Fr::ZERO,
        epoch: Fr::ZERO,
    };
    
    // ✅ Sửa lỗi TrivialCircuit cho đúng chuẩn 0.34.0
    let circuit_secondary = TrivialCircuit::<<VestaEngine as Engine>::Scalar>::default(); //circuit phụ (secondary circuit) đơn giản, không có logic nào, chỉ để hỗ trợ quá trình folding của SNARK
    
    println!("\n🔧 Đang thiết lập Public Params...");
    let start_setup = Instant::now();
    //thiết lập tham số công khai (public parameters) cho SNARK
    //PallasEngine vs VestaEngine:
        //Pallas: Dùng cho primary proof (bằng chứng chính)
        //Vesta: Dùng cho secondary proof (hỗ trợ folding)
        //Chúng là "cặp curve" (cycle of curves) - đặc biệt cho Nova
    //&circuit_primary:
        //Dấu & nghĩa là mượn (borrow), không lấy ownership, truyền tham chiếu đến circuit_primary
        //Truyền circuit mẫu để setup biết cấu trúc và các ràng buộc cần thiết cho quá trình tạo bằng chứng
    //&*default_ck_hint():
        //default_ck_hint(): Trả về Box<dyn CommitmentKeyHint> (hộp chứa trait object)
        //*: Dereference (lấy giá trị bên trong Box)
        // //&: Mượn giá trị đó
        // Mục đích: Tối ưu hóa việc tạo commitment key
    let pp = PublicParams::<
        PallasEngine,
        VestaEngine,
        PoStStepCircuit,
        TrivialCircuit<<VestaEngine as Engine>::Scalar>,
    >::setup(
        &circuit_primary,
        &circuit_secondary,
        &*nova_snark::traits::snark::default_ck_hint(),
        &*nova_snark::traits::snark::default_ck_hint(),
    );
    println!("   ✅ Hoàn tất sau {:?}", start_setup.elapsed());
    
    let z0_primary = vec![initial_state];//vector chứa trạng thái ban đầu cho primary circuit
    let z0_secondary = vec![<VestaEngine as Engine>::Scalar::ZERO];//vector chứa trạng thái ban đầu cho secondary circuit (đơn giản là số 0)
    //tạo SNARK đệ quy với các tham số đã thiết lập và trạng thái ban đầu
    let mut recursive_snark = RecursiveSNARK::new(
        &pp,
        &circuit_primary,
        &circuit_secondary,
        &z0_primary,
        &z0_secondary,
    ).expect("Lỗi khởi tạo SNARK");
    
    println!("\n⏰ Bắt đầu chạy các Epoch...");
    let num_epochs = 3;
    let mut rng = rand::thread_rng();
    //chạy các epoch để tạo bằng chứng cho mỗi bước, sử dụng dữ liệu sector và các tham số ngẫu nhiên
    for epoch in 0..num_epochs {
        let challenge_random = Fr::from(rng.gen::<u64>());
        let epoch_fr = Fr::from(epoch as u64);
        
        let step_circuit = PoStStepCircuit {
            challenge_random,
            sector_commitment: sector.commitment,
            epoch: epoch_fr,
        };
        
        let start_prove = Instant::now();
        let result = recursive_snark.prove_step(
            &pp,
            &step_circuit,
            &circuit_secondary,
        );
        
        match result {
            Ok(_) => println!("      ✅ Epoch {} folding thành công sau {:?}", epoch + 1, start_prove.elapsed()),
            Err(e) => { println!("      ❌ Lỗi Epoch {}: {:?}", epoch + 1, e); return; }
        }
    }
    
    println!("\n🔍 Đang xác minh bằng chứng...");
    let start_verify = Instant::now();
    let verify_result = recursive_snark.verify(&pp, num_epochs, &z0_primary, &z0_secondary);
    println!("   ⏱️  Thời gian verify: {:?}", start_verify.elapsed());
    
    match verify_result {
        Ok((final_state, _)) => {
            println!("  ✅✅✅  XÁC MINH THÀNH CÔNG! Final state: {:?}", final_state[0]);
        }
        Err(e) => println!("  ❌❌❌  LỖI XÁC MINH: {:?}", e),
    }
}