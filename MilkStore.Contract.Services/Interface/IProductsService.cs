using MilkStore.Contract.Repositories.Entity;
using MilkStore.Core;
using MilkStore.ModelViews.ProductsModelViews;

namespace MilkStore.Contract.Services.Interface
{
    public interface IProductsService
    {
        Task<IEnumerable<ProductsModel>> GetProducts(string? id);
        Task<Products> CreateProducts(ProductsModel productsModel);
        Task<Products> UpdateProducts(string id,ProductsModel productsModel);
        Task<Products> DeleteProducts(object id);
        Task<BasePaginatedList<Products>> PagingProducts(int page, int pageSize);
        Task<IEnumerable<ProductsModel>> GetProductsName(string? Name);
    }
}
