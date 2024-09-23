using AutoMapper;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.ModelViews.GiftModelViews;
using MilkStore.Repositories.Context;

namespace MilkStore.Services.Service
{
    public class GiftService : IGiftService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly DatabaseContext context;
        private readonly IMapper _mapper;
        public GiftService(DatabaseContext context, IUnitOfWork unitOfWork, IMapper mapper)
        {
            this.context = context;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }
        public async Task<Gift> CreateGift(GiftModel GiftModel)
        {
            Gift newGift = _mapper.Map<Gift>(GiftModel);
            newGift.CreatedTime = DateTime.UtcNow;

            await _unitOfWork.GetRepository<Gift>().InsertAsync(newGift);
            await _unitOfWork.SaveAsync();

            return newGift;
        }

        public async Task<Gift> DeleteGift(object id)
        {
            Gift Gift = await _unitOfWork.GetRepository<Gift>().GetByIdAsync(id);

            if (Gift.DeletedTime != null)
            {
                throw new Exception($"Mã quà tặng đã được xóa:{id}");
            }
            Gift.DeletedTime = DateTime.UtcNow;
            await _unitOfWork.GetRepository<Gift>().UpdateAsync(Gift);
            await _unitOfWork.SaveAsync();

            return Gift;
        }

        public async Task<IEnumerable<GiftModel>> GetGift(string? id)
        {
            if (id == null)
            {
                // Lấy tất cả sản phẩm
                IEnumerable<Gift> Gift = await _unitOfWork.GetRepository<Gift>().GetAllAsync();

                // Lọc sản phẩm có DeleteTime == null
                Gift = Gift.Where(p => p.DeletedTime == null);

                return _mapper.Map<IEnumerable<GiftModel>>(Gift);
            }
            else
            {
                // Lấy sản phẩm theo ID
                Gift Gift = await _unitOfWork.GetRepository<Gift>().GetByIdAsync(id);

                if (Gift != null && Gift.DeletedTime == null) // Kiểm tra DeleteTime
                {
                    return new List<GiftModel> { _mapper.Map<GiftModel>(Gift) };
                }
                else
                {
                    return new List<GiftModel>();
                }
            }
        }

        public async Task<BasePaginatedList<Gift>> PagingGift(int pageIndex, int pageSize)
        {
            IQueryable<Gift> query = _unitOfWork.GetRepository<Gift>().Entities;
            // Sử dụng hàm GetPagging để lấy danh sách phân trang
            BasePaginatedList<Gift> paginatedList = await _unitOfWork.GetRepository<Gift>().GetPagging(query, pageIndex, pageSize);
            //return new BasePaginatedList<T>(items, count, index, pageSize);
            return paginatedList; // Trả về danh sách phân trang
        }

        public async Task<Gift> UpdateGift(string id, GiftModel GiftModel)
        {
            Gift existingGift = await _unitOfWork.GetRepository<Gift>().GetByIdAsync(id);

            if (existingGift == null)
            {
                throw new Exception("Sản phẩm không tồn tại.");
            }

            // Cập nhật thông tin sản phẩm bằng cách ánh xạ từ DTO
            _mapper.Map(GiftModel, existingGift);
            existingGift.LastUpdatedTime = DateTime.UtcNow;

            await _unitOfWork.GetRepository<Gift>().UpdateAsync(existingGift);
            await _unitOfWork.SaveAsync();

            return existingGift;
        }
    }
}
