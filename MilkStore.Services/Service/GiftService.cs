using AutoMapper;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.ModelViews.GiftModelViews;
using MilkStore.ModelViews.ResponseDTO;
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
        public async Task CreateGift(GiftModel GiftModel)
        {  
            IEnumerable<Gift> g = await _unitOfWork.GetRepository<Gift>().GetAllAsync();
            foreach (var iem in g)
            {
                if(iem.ProductId.Equals(GiftModel.ProductId, StringComparison.OrdinalIgnoreCase) && !iem.DeletedTime.HasValue)
                {
                    throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Same gift");
                }    
            }
            Gift newGift = _mapper.Map<Gift>(GiftModel);
            newGift.CreatedTime = DateTime.UtcNow;
            await _unitOfWork.GetRepository<Gift>().InsertAsync(newGift);
            await _unitOfWork.SaveAsync();
        }

        public async Task DeleteGift(string id)
        {
            if(string.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Input wrong id");
            }    
            Gift Gift = await _unitOfWork.GetRepository<Gift>().GetByIdAsync(id) ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Gift null");

            if (Gift.DeletedTime != null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Doesn't exist:{id}");
            }
            Gift.DeletedTime = DateTime.UtcNow;
            await _unitOfWork.GetRepository<Gift>().UpdateAsync(Gift);
            await _unitOfWork.SaveAsync();
        }


        public async Task<BasePaginatedList<GiftResponseDTO>> GetGift(string? id, int pageIndex, int pageSize)
        {
            if (pageIndex == 0 || pageSize == 0)
            {
                pageSize = 5;
                pageIndex = 1;
            }
            // Kiểm tra nếu không truyền ID thì thực hiện phân trang
            if (id == null)
            {
                // Lấy toàn bộ danh sách quà tặng chưa bị xóa
                IQueryable<Gift> query = _unitOfWork.GetRepository<Gift>().Entities;
                query = query.Where(p => p.DeletedTime == null);

                // Thực hiện phân trang
                BasePaginatedList<Gift> paginatedList = await _unitOfWork.GetRepository<Gift>().GetPagging(query, pageIndex, pageSize);

                // Chuyển đổi sang DTO và trả về danh sách phân trang
                var giftModel = _mapper.Map<IEnumerable<GiftResponseDTO>>(paginatedList.Items);
                return new BasePaginatedList<GiftResponseDTO>(giftModel.ToList(), paginatedList.TotalPages, pageIndex, pageSize);
            }
            else
            {
                // Lấy quà tặng theo ID
                Gift gift = await _unitOfWork.GetRepository<Gift>().GetByIdAsync(id)?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Gift null");

                // Nếu quà tặng tồn tại và chưa bị xóa, trả về kết quả
                if (gift != null && gift.DeletedTime == null)
                {
                    return new BasePaginatedList<GiftResponseDTO>(new List<GiftResponseDTO> { _mapper.Map<GiftResponseDTO>(gift) }, 1, 1, 1); // Trả về 1 kết quả
                }
                else
                {
                    return new BasePaginatedList<GiftResponseDTO>(new List<GiftResponseDTO>(), 0, 1, 1); // Trả về rỗng nếu không tìm thấy
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

        public async Task UpdateGift(string id, GiftModel GiftModel)
        {
            IEnumerable<Gift> g = await _unitOfWork.GetRepository<Gift>().GetAllAsync();
            foreach (var iem in g)
            {
                if (iem.ProductId.Equals(GiftModel.ProductId, StringComparison.OrdinalIgnoreCase) && !iem.DeletedTime.HasValue && iem.Id != id)
                {
                    throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Same gift");
                }
            }
            if (string.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Input wrong id");
            }    
            Gift existingGift = await _unitOfWork.GetRepository<Gift>().GetByIdAsync(id) ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Doesn't exist:{id}");


            // Cập nhật thông tin sản phẩm bằng cách ánh xạ từ DTO
            _mapper.Map(GiftModel, existingGift);
            existingGift.LastUpdatedTime = DateTime.UtcNow;

            await _unitOfWork.GetRepository<Gift>().UpdateAsync(existingGift);
            await _unitOfWork.SaveAsync();
        }
    }
}
