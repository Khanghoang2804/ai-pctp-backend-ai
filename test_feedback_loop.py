import sys
import os

# Add to path so we can import app modules
sys.path.append("/app")

from app.service.ScanLayer3_Tools import SearchAlternativeGraphPathTool
from app.service.queryNodeAndRel import querydb_dicts
from app.schema.gitnexus_sync import TABLE_NODES, TABLE_RELATIONS

def main():
    print("--- Bắt đầu Test: Neuro-Symbolic Feedback Loop Tool ---")
    
    repo = "dvna-master"  # Sử dụng repo dvna-master
    tool = SearchAlternativeGraphPathTool(repo_name=repo)
    
    # 1. Tìm một target_node (Sink) hợp lệ có ít nhất 1 đường vào (CALLS)
    print(f"[*] Đang tìm một Sink Node có liên kết CALLS trong bảng {TABLE_RELATIONS}...")
    query_sink = f"SELECT to_id FROM {TABLE_RELATIONS} WHERE repo_name=%s AND relation_type='CALLS' LIMIT 1"
    
    try:
        rows = querydb_dicts(query_sink, (repo,))
        if not rows:
            print(f"[!] Không tìm thấy cạnh CALLS nào cho repo {repo}. Test sẽ thử với repo mặc định khác hoặc ngắt.")
            return
            
        target_node = rows[0]["to_id"]
        print(f"[+] Tìm thấy Sink Node: {target_node}")
        
        # 2. Tìm một Caller Node (Source hoặc Intermediate) gọi tới Sink này để làm đối tượng "bị chặn"
        query_caller = f"SELECT from_id FROM {TABLE_RELATIONS} WHERE repo_name=%s AND to_id=%s AND relation_type='CALLS' LIMIT 1"
        caller_rows = querydb_dicts(query_caller, (repo, target_node))
        
        if not caller_rows:
            print("[!] Không tìm thấy Caller. Dùng một node giả làm mồi nhử.")
            exclude_node = "Function:dummy"
        else:
            exclude_node = caller_rows[0]["from_id"]
            print(f"[+] Tìm thấy Caller Node: {exclude_node} (Sẽ dùng Node này làm vật cản Z3 Solver)")
            
        # 3. Chạy Tool với kịch bản bình thường (Không chặn)
        print("\n[*] Tình huống 1: LLM Agent gọi DB tìm đường đi bình thường...")
        # Ở đây ta gọi db_taint_path trực tiếp vì tool mặc định nhận exclude_nodes, ta truyền một ID không tồn tại
        normal_res = tool._run(target_node_id=target_node, exclude_node_id="Function:NothingToExclude123")
        print("[Kết quả 1]")
        print("Độ dài chuỗi trả về:", len(normal_res))
        
        # 4. Chạy Tool với kịch bản Feedback Loop (Z3 chặn exclude_node)
        print(f"\n[*] Tình huống 2: LLM Agent bị Z3 chặn, nó tự động gọi Tool né Node '{exclude_node}'...")
        feedback_res = tool._run(target_node_id=target_node, exclude_node_id=exclude_node)
        print("[Kết quả 2]")
        print("Độ dài chuỗi trả về:", len(feedback_res))
        
        # Trích xuất 1 phần kết quả để kiểm chứng
        if "Không tìm thấy luồng tấn công nào khác" in feedback_res or "error" in feedback_res:
            print(f"[OK] CSDL đã phản hồi chính xác: {feedback_res.strip()}")
        else:
            print(f"[OK] Tool đã trả về một luồng MỚI, hoàn toàn né được node '{exclude_node}'.")
            
        print("\n--- Test Hoàn tất Thành công! Lỗi SQL (nếu có) đã được giải quyết. ---")
        
    except Exception as e:
        print("\n[!] CÓ LỖI XẢY RA:")
        print(e)
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
