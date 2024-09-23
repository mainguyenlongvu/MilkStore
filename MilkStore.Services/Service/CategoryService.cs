using AutoMapper;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.ModelViews.CategoryModelViews;
using MilkStore.Repositories.Context;

namespace MilkStore.Services.Service
{
    public class CategoryService : ICategoryService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly DatabaseContext context;
        private readonly IMapper _mapper;
        public CategoryService(DatabaseContext context, IUnitOfWork unitOfWork, IMapper mapper)
        {
            this.context = context;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }
        public async Task<BasePaginatedList<Category>> PagingCategory(int pageIndex, int pageSize)
        {
            IQueryable<Category> query = _unitOfWork.GetRepository<Category>().Entities;
            // Sử dụng hàm GetPagging để lấy danh sách phân trang
            BasePaginatedList<Category> paginatedList = await _unitOfWork.GetRepository<Category>().GetPagging(query, pageIndex, pageSize);
            //return new BasePaginatedList<T>(items, count, index, pageSize);
            return paginatedList; // Trả về danh sách phân trang
        }
        public async Task<Category> CreateCategory(CategoryModel CategoryModel)
        {
            Category newCategory = _mapper.Map<Category>(CategoryModel);
            newCategory.CreatedTime = DateTime.UtcNow;

            await _unitOfWork.GetRepository<Category>().InsertAsync(newCategory);
            await _unitOfWork.SaveAsync();

            return newCategory;
        }
        public async Task<Category> DeleteCategory(object id)
        {
            Category Category = await _unitOfWork.GetRepository<Category>().GetByIdAsync(id);

            if (Category.DeletedTime != null)
            {
                throw new Exception($"Mã hàng đã được xóa:{id}");
            }
            Category.DeletedTime = DateTime.UtcNow;
            await _unitOfWork.GetRepository<Category>().UpdateAsync(Category);
            await _unitOfWork.SaveAsync();

            return Category;
        }


        public async Task<IEnumerable<CategoryModel>> GetCategory(string? id)
        {
            if (id == null)
            {
                // Lấy tất cả sản phẩm
                IEnumerable<Category> Category = await _unitOfWork.GetRepository<Category>().GetAllAsync();

                // Lọc sản phẩm có DeleteTime == null
                Category = Category.Where(p => p.DeletedTime == null);

                return _mapper.Map<IEnumerable<CategoryModel>>(Category);
            }
            else
            {
                // Lấy sản phẩm theo ID
                Category product = await _unitOfWork.GetRepository<Category>().GetByIdAsync(id);

                if (product != null && product.DeletedTime == null) // Kiểm tra DeleteTime
                {
                    return new List<CategoryModel> { _mapper.Map<CategoryModel>(product) };
                }
                else
                {
                    return new List<CategoryModel>();
                }
            }
        }


        public async Task<Category> UpdateCategory(string id, CategoryModel CategoryModel)
        {
            Category existingCategory = await _unitOfWork.GetRepository<Category>().GetByIdAsync(id);

            if (existingCategory == null)
            {
                throw new Exception("Sản phẩm không tồn tại.");
            }

            // Cập nhật thông tin sản phẩm bằng cách ánh xạ từ DTO
            _mapper.Map(CategoryModel, existingCategory);
            existingCategory.LastUpdatedTime = DateTime.UtcNow;

            await _unitOfWork.GetRepository<Category>().UpdateAsync(existingCategory);
            await _unitOfWork.SaveAsync();

            return existingCategory;
        }


    }
}
