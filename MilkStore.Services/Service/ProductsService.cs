using AutoMapper;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.ModelViews.ProductsModelViews;
using MilkStore.Repositories.Context;

namespace MilkStore.Services.Service
{
    public class ProductsService : IProductsService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly DatabaseContext context;
        private readonly IMapper _mapper;
        public ProductsService(DatabaseContext context, IUnitOfWork unitOfWork, IMapper mapper)
        {
            this.context = context;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }
        public async Task<IEnumerable<ProductsModel>> GetProductsName(string? name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentNullException(nameof(name), "Tên sản phẩm không được để trống.");
            }
            IEnumerable<Products> products = await _unitOfWork.GetRepository<Products>().GetAllAsync();

            products = products.Where(p => p.ProductName.Contains(name, StringComparison.OrdinalIgnoreCase) && p.DeletedTime == null);

            return _mapper.Map<IEnumerable<ProductsModel>>(products);
        }
        public async Task<BasePaginatedList<Products>> PagingProducts(int pageIndex, int pageSize)
        {
            IQueryable<Products> query = _unitOfWork.GetRepository<Products>().Entities;
            // Sử dụng hàm GetPagging để lấy danh sách phân trang
            BasePaginatedList<Products> paginatedList = await _unitOfWork.GetRepository<Products>().GetPagging(query, pageIndex, pageSize);
            //return new BasePaginatedList<T>(items, count, index, pageSize);
            return paginatedList; // Trả về danh sách phân trang
        }
        public async Task<Products> CreateProducts(ProductsModel productsModel)
        {
            Products newProduct = _mapper.Map<Products>(productsModel);
            newProduct.CreatedTime = DateTime.UtcNow;

            await _unitOfWork.GetRepository<Products>().InsertAsync(newProduct);
            await _unitOfWork.SaveAsync();

            return newProduct;
        }
        public async Task<Products> DeleteProducts(object id)
        {
            Products product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(id);

            if (product.DeletedTime != null)
            {
                throw new Exception($"Mã hàng đã được xóa:{id}");
            }
            product.DeletedTime = DateTime.UtcNow;
            await _unitOfWork.GetRepository<Products>().UpdateAsync(product);
            await _unitOfWork.SaveAsync();

            return product;
        }


        public async Task<IEnumerable<ProductsModel>> GetProducts(string? id)
        {
            if (id == null)
            {
                // Lấy tất cả sản phẩm
                IEnumerable<Products> products = await _unitOfWork.GetRepository<Products>().GetAllAsync();

                // Lọc sản phẩm có DeleteTime == null
                products = products.Where(p => p.DeletedTime == null);

                return _mapper.Map<IEnumerable<ProductsModel>>(products);
            }
            else
            {
                // Lấy sản phẩm theo ID
                Products product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(id);

                if (product != null && product.DeletedTime == null) // Kiểm tra DeleteTime
                {
                    return new List<ProductsModel> { _mapper.Map<ProductsModel>(product) };
                }
                else
                {
                    return new List<ProductsModel>();
                }
            }
        }




        public async Task<Products> UpdateProducts(string id, ProductsModel productsModel)
        {
            Products existingProduct = await _unitOfWork.GetRepository<Products>().GetByIdAsync(id);

            if (existingProduct == null)
            {
                throw new Exception("Sản phẩm không tồn tại.");
            }

            // Cập nhật thông tin sản phẩm bằng cách ánh xạ từ DTO
            _mapper.Map(productsModel, existingProduct);
            existingProduct.LastUpdatedTime = DateTime.UtcNow;

            await _unitOfWork.GetRepository<Products>().UpdateAsync(existingProduct);
            await _unitOfWork.SaveAsync();

            return existingProduct;
        }
    }
}
